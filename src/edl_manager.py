"""
EDL (External Dynamic List) Manager

管理 PA / GlobalProtect 用的 EDL 檔案，支援：
- 新增 entry（IP / URL / Domain），自動分類
- TTL sliding window 自動延期；TTL = -1 永不過期
- 產生符合 GlobalProtect 規範的純文字 EDL 檔案
- Pending 佇列 + 確認機制
- PATCH /edl/entry/{value} 可動態修改 per-entry TTL
"""

import ipaddress
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .expiry_policy import ExpiryPolicy

logger = logging.getLogger(__name__)

EntryType = Literal["ip", "url", "domain"]


class EDLEntry:
    def __init__(
        self,
        value: str,
        added_at: str | None = None,
        ttl_days: int = 30,
        last_activity: str | None = None,
        source_signature: str = "",
        source_event_id: str = "",
        added_by: str = "auto",
        entry_type: str | None = None,
    ):
        self.value = value
        self.added_at = added_at or datetime.now(timezone.utc).isoformat()
        self.source_signature = source_signature
        self.source_event_id = source_event_id
        self.added_by = added_by
        self.entry_type: str = entry_type or EDLManager.classify_entry(value)

        # Sliding window TTL: use last_activity if given, else fall back to added_at
        la_str = last_activity or self.added_at
        self.expiry = ExpiryPolicy(
            ttl_days=ttl_days,
            last_activity=datetime.fromisoformat(la_str),
        )

    # Backward-compat properties so existing code / tests still work
    @property
    def ttl_days(self) -> int:
        return self.expiry.ttl_days

    @property
    def is_expired(self) -> bool:
        return self.expiry.is_expired()

    @property
    def expires_at(self) -> datetime | None:
        if self.expiry.ttl_days == -1:
            return None
        from datetime import timedelta
        base = self.expiry.last_activity or datetime.fromisoformat(self.added_at)
        return base + timedelta(days=self.expiry.ttl_days)

    def to_dict(self) -> dict:
        ea = self.expires_at
        return {
            "value":            self.value,
            "added_at":         self.added_at,
            "ttl_days":         self.expiry.ttl_days,
            "last_activity":    self.expiry.last_activity.isoformat() if self.expiry.last_activity else None,
            "expires_at":       ea.isoformat() if ea else None,
            "entry_type":       self.entry_type,
            "source_signature": self.source_signature,
            "source_event_id":  self.source_event_id,
            "added_by":         self.added_by,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EDLEntry":
        # Backward compat: old format has no last_activity, use added_at
        last_activity = data.get("last_activity") or data.get("added_at")
        return cls(
            value=data["value"],
            added_at=data.get("added_at"),
            ttl_days=data.get("ttl_days", 30),
            last_activity=last_activity,
            source_signature=data.get("source_signature", ""),
            source_event_id=data.get("source_event_id", ""),
            added_by=data.get("added_by", "auto"),
            entry_type=data.get("entry_type"),
        )


class PendingEntry:
    """EDL 待審條目，需人工確認後才正式寫入。"""

    def __init__(
        self,
        value: str,
        token: str | None = None,
        suggested_at: str | None = None,
        source_signature: str = "",
        source_event_id: str = "",
        status: str = "pending",  # pending | approved | rejected
    ):
        self.value = value
        self.token = token or str(uuid.uuid4())
        self.suggested_at = suggested_at or datetime.now(timezone.utc).isoformat()
        self.source_signature = source_signature
        self.source_event_id = source_event_id
        self.status = status

    def to_dict(self) -> dict:
        return {
            "value":            self.value,
            "token":            self.token,
            "suggested_at":     self.suggested_at,
            "source_signature": self.source_signature,
            "source_event_id":  self.source_event_id,
            "status":           self.status,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PendingEntry":
        return cls(
            value=data["value"],
            token=data.get("token"),
            suggested_at=data.get("suggested_at"),
            source_signature=data.get("source_signature", ""),
            source_event_id=data.get("source_event_id", ""),
            status=data.get("status", "pending"),
        )


class EDLManager:
    def __init__(self, config: dict):
        edl_cfg = config.get("edl", {})
        self.output_dir = Path(edl_cfg.get("output_dir", "/var/www/edl"))
        self.default_ttl_days = edl_cfg.get("default_ttl_days", 30)
        self.metadata_path = self.output_dir / "edl_metadata.json"
        self.pending_path = self.output_dir / "edl_pending.json"

        # EDL files served to PAN / GlobalProtect
        self.edl_files: dict[str, Path] = {
            "ip":     self.output_dir / "block_ip.txt",
            "url":    self.output_dir / "block_url.txt",
            "domain": self.output_dir / "block_domain.txt",
        }

        self._entries: list[EDLEntry] = []
        self._pending: list[PendingEntry] = []
        self._load_metadata()
        self._load_pending()

    # ------------------------------------------------------------------
    # Entry type classification
    # ------------------------------------------------------------------

    @staticmethod
    def classify_entry(value: str) -> str:
        """Classify a value as 'ip', 'url', or 'domain'."""
        try:
            ipaddress.ip_network(value, strict=False)
            return "ip"
        except ValueError:
            pass
        if value.startswith(("http://", "https://", "*.")):
            return "url"
        return "domain"

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_metadata(self):
        if not self.metadata_path.exists():
            self._entries = []
            return
        try:
            with open(self.metadata_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._entries = [EDLEntry.from_dict(e) for e in data]
            logger.info(f"Loaded {len(self._entries)} EDL entries from metadata.")
        except Exception as e:
            logger.error(f"Failed to load EDL metadata: {e}")
            self._entries = []

    def _save_metadata(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        with open(self.metadata_path, "w", encoding="utf-8") as f:
            json.dump([e.to_dict() for e in self._entries], f, indent=2, ensure_ascii=False)

    def _load_pending(self):
        if not self.pending_path.exists():
            self._pending = []
            return
        try:
            with open(self.pending_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._pending = [PendingEntry.from_dict(e) for e in data]
            pending_count = sum(1 for e in self._pending if e.status == "pending")
            logger.info(f"Loaded {len(self._pending)} pending entries ({pending_count} awaiting approval).")
        except Exception as e:
            logger.error(f"Failed to load EDL pending queue: {e}")
            self._pending = []

    def _save_pending(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        with open(self.pending_path, "w", encoding="utf-8") as f:
            json.dump([e.to_dict() for e in self._pending], f, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # EDL file generation (GlobalProtect format)
    # ------------------------------------------------------------------

    def _regenerate_edl_files(self):
        """Generate three plain-text EDL files in GlobalProtect format."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        buckets: dict[str, list[str]] = {"ip": [], "url": [], "domain": []}
        for entry in self._entries:
            if entry.is_expired:
                continue
            et = entry.entry_type or self.classify_entry(entry.value)
            buckets[et].append(entry.value)

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for edl_type, items in buckets.items():
            items = sorted(set(items))
            path = self.edl_files[edl_type]
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write("# Generated by Graylog Threat Analyzer\n")
                f.write(f"# Updated: {now_str}\n")
                f.write(f"# Count: {len(items)}\n")
                for item in items:
                    f.write(item + "\n")
            logger.info(f"EDL {edl_type}: {len(items)} entries written to {path}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def suggest_entry(self, value: str, source_event: dict | None = None) -> str:
        """Queue an EDL entry for human approval. Returns confirmation token."""
        existing_active = next((e for e in self._entries if e.value == value and not e.is_expired), None)
        if existing_active:
            logger.info(f"EDL suggest_entry: {value} already active, returning sentinel token.")
            return f"already-active:{value}"

        for entry in self._pending:
            if entry.value == value and entry.status == "pending":
                logger.info(f"EDL pending entry already exists for {value}, reusing token.")
                return entry.token

        source_event = source_event or {}
        pending = PendingEntry(
            value=value,
            source_signature=source_event.get("alert_signature", ""),
            source_event_id=source_event.get("event_uid", ""),
        )
        self._pending.append(pending)
        self._save_pending()
        logger.info(f"EDL suggestion queued: {value} (token={pending.token})")
        return pending.token

    def approve_entry(self, token: str) -> tuple[bool, str]:
        """Approve a pending entry and write it to the EDL."""
        if token.startswith("already-active:"):
            value = token[len("already-active:"):]
            return False, f"{value} 已存在於 EDL 封鎖清單中，無需重複加入。"
        for entry in self._pending:
            if entry.token == token:
                if entry.status == "approved":
                    return False, f"{entry.value} 已於先前確認加入 EDL。"
                if entry.status == "rejected":
                    return False, f"{entry.value} 已被拒絕，無法再次確認。"

                added = self.add_entry(
                    value=entry.value,
                    source_signature=entry.source_signature,
                    source_event_id=entry.source_event_id,
                    added_by="approved-via-email",
                )
                entry.status = "approved"
                self._save_pending()

                if added:
                    logger.info(f"EDL entry approved and added: {entry.value} (token={token})")
                    return True, f"{entry.value} 已成功加入 EDL 封鎖清單。"
                else:
                    return False, f"{entry.value} 已存在於 EDL 中（無需重複加入）。"

        return False, f"找不到 token={token} 的待審條目，可能已過期或不存在。"

    def reject_entry(self, token: str) -> tuple[bool, str]:
        """Reject a pending entry (not written to EDL)."""
        for entry in self._pending:
            if entry.token == token:
                if entry.status != "pending":
                    return False, f"條目狀態為 {entry.status}，無法拒絕。"
                entry.status = "rejected"
                self._save_pending()
                logger.info(f"EDL entry rejected: {entry.value} (token={token})")
                return True, f"{entry.value} 已標記為拒絕，不會加入 EDL。"

        return False, f"找不到 token={token} 的待審條目。"

    def list_pending(self) -> list[dict]:
        return [e.to_dict() for e in self._pending if e.status == "pending"]

    def add_entry(
        self,
        value: str,
        ttl_days: int | None = None,
        source_signature: str = "",
        source_event_id: str = "",
        added_by: str = "auto",
    ) -> bool:
        """
        Add an entry to the EDL.
        If entry already exists and is not expired, reset its TTL (sliding window).
        Returns True if a new entry was created, False if existing was updated.
        """
        effective_ttl = ttl_days if ttl_days is not None else self.default_ttl_days
        existing = next((e for e in self._entries if e.value == value and not e.is_expired), None)
        if existing:
            existing.expiry.touch()
            self._save_metadata()
            logger.info(f"EDL entry TTL reset (sliding window): {value}")
            return False

        entry = EDLEntry(
            value=value,
            ttl_days=effective_ttl,
            source_signature=source_signature,
            source_event_id=source_event_id,
            added_by=added_by,
        )
        self._entries.append(entry)
        self._save_metadata()
        self._regenerate_edl_files()
        logger.info(f"EDL entry added: {value} (TTL: {entry.ttl_days} days, type: {entry.entry_type})")
        return True

    def remove_entry(self, value: str) -> bool:
        before = len(self._entries)
        self._entries = [e for e in self._entries if e.value != value]
        if len(self._entries) < before:
            self._save_metadata()
            self._regenerate_edl_files()
            logger.info(f"EDL entry removed: {value}")
            return True
        return False

    def update_entry_ttl(self, value: str, ttl_days: int) -> bool:
        """Update TTL for an existing entry. ttl_days = -1 = permanent."""
        for entry in self._entries:
            if entry.value == value:
                entry.expiry.ttl_days = ttl_days
                self._save_metadata()
                logger.info(f"EDL entry TTL updated: {value} → {ttl_days} days")
                return True
        return False

    def cleanup_expired(self) -> int:
        before = len(self._entries)
        expired = [e for e in self._entries if e.is_expired]
        self._entries = [e for e in self._entries if not e.is_expired]
        removed = before - len(self._entries)

        if removed > 0:
            for e in expired:
                logger.info(f"EDL expired: {e.value} (added: {e.added_at})")
            self._save_metadata()
            self._regenerate_edl_files()

        return removed

    def list_entries(self) -> list[dict]:
        return [e.to_dict() for e in self._entries if not e.is_expired]

    def is_active(self, value: str) -> bool:
        """Return True if value matches a confirmed, non-expired EDL entry (exact or CIDR)."""
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            addr = None

        for e in self._entries:
            if e.is_expired:
                continue
            if e.value == value:
                return True
            if addr is not None and e.entry_type == "ip":
                try:
                    if addr in ipaddress.ip_network(e.value, strict=False):
                        return True
                except ValueError:
                    pass
        return False

    def get_pending_value(self, token: str) -> str | None:
        """Return the value associated with a pending token, or None."""
        for entry in self._pending:
            if entry.token == token:
                return entry.value
        return None
