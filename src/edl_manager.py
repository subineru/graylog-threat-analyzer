"""
EDL (External Dynamic List) Manager

管理 PA 防火牆用的 EDL 檔案，支援：
- 新增 entry（IP / URL / Domain）
- TTL 自動過期移除
- 產生純文字 EDL 檔案供 PA 拉取
- Pending 佇列 + 確認機制（高信心異常先送審，點擊 email 連結後才正式寫入）
"""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class EDLEntry:
    def __init__(
        self,
        value: str,
        added_at: str | None = None,
        ttl_days: int = 30,
        source_signature: str = "",
        source_event_id: str = "",
        added_by: str = "auto",
    ):
        self.value = value
        self.added_at = added_at or datetime.now(timezone.utc).isoformat()
        self.ttl_days = ttl_days
        self.source_signature = source_signature
        self.source_event_id = source_event_id
        self.added_by = added_by

    @property
    def expires_at(self) -> datetime:
        added = datetime.fromisoformat(self.added_at)
        return added + timedelta(days=self.ttl_days)

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "added_at": self.added_at,
            "ttl_days": self.ttl_days,
            "expires_at": self.expires_at.isoformat(),
            "source_signature": self.source_signature,
            "source_event_id": self.source_event_id,
            "added_by": self.added_by,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EDLEntry":
        return cls(
            value=data["value"],
            added_at=data.get("added_at"),
            ttl_days=data.get("ttl_days", 30),
            source_signature=data.get("source_signature", ""),
            source_event_id=data.get("source_event_id", ""),
            added_by=data.get("added_by", "auto"),
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
            "value": self.value,
            "token": self.token,
            "suggested_at": self.suggested_at,
            "source_signature": self.source_signature,
            "source_event_id": self.source_event_id,
            "status": self.status,
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

        # EDL 檔案路徑（PA 會拉取這些）
        self.edl_files = {
            "ip": self.output_dir / "block_ip.txt",
            "url": self.output_dir / "block_url.txt",
            "domain": self.output_dir / "block_domain.txt",
        }

        self._entries: list[EDLEntry] = []
        self._pending: list[PendingEntry] = []
        self._load_metadata()
        self._load_pending()

    def _load_metadata(self):
        """從 metadata 檔載入現有 entries"""
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
        """儲存 metadata"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        with open(self.metadata_path, "w", encoding="utf-8") as f:
            json.dump([e.to_dict() for e in self._entries], f, indent=2, ensure_ascii=False)

    def _load_pending(self):
        """載入 pending 佇列"""
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
        """儲存 pending 佇列"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        with open(self.pending_path, "w", encoding="utf-8") as f:
            json.dump([e.to_dict() for e in self._pending], f, indent=2, ensure_ascii=False)

    def _regenerate_edl_files(self):
        """從 metadata 重新產生純文字 EDL 檔案"""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        ips, urls, domains = [], [], []
        for entry in self._entries:
            if entry.is_expired:
                continue
            v = entry.value
            if v.startswith("http://") or v.startswith("https://"):
                urls.append(v)
            elif "." in v and not any(c == "/" for c in v):
                parts = v.split(".")
                if all(p.isdigit() for p in parts):
                    ips.append(v)
                else:
                    domains.append(v)
            else:
                ips.append(v)

        for edl_type, items, path in [
            ("ip", ips, self.edl_files["ip"]),
            ("url", urls, self.edl_files["url"]),
            ("domain", domains, self.edl_files["domain"]),
        ]:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(set(items))))
                if items:
                    f.write("\n")
            logger.info(f"EDL {edl_type}: {len(items)} entries written to {path}")

    def suggest_entry(self, value: str, source_event: dict | None = None) -> str:
        """
        將 EDL 條目加入待審佇列，回傳確認用的 token。
        高信心異常事件觸發此方法，需人工點擊 email 連結確認後才正式寫入 EDL。
        """
        # 如果已有相同 value 的 pending 條目，直接回傳其 token（避免重複）
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
        """
        確認 pending 條目，正式寫入 EDL。
        回傳 (success, message)。
        """
        for entry in self._pending:
            if entry.token == token:
                if entry.status == "approved":
                    return False, f"{entry.value} 已於先前確認加入 EDL。"
                if entry.status == "rejected":
                    return False, f"{entry.value} 已被拒絕，無法再次確認。"

                # 正式加入 EDL
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
        """拒絕 pending 條目（不寫入 EDL）。"""
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
        """列出所有待審條目"""
        return [e.to_dict() for e in self._pending if e.status == "pending"]

    def add_entry(
        self,
        value: str,
        ttl_days: int | None = None,
        source_signature: str = "",
        source_event_id: str = "",
        added_by: str = "auto",
    ) -> bool:
        """正式新增一筆 EDL entry"""
        existing = [e for e in self._entries if e.value == value and not e.is_expired]
        if existing:
            logger.info(f"EDL entry already exists: {value}")
            return False

        entry = EDLEntry(
            value=value,
            ttl_days=ttl_days or self.default_ttl_days,
            source_signature=source_signature,
            source_event_id=source_event_id,
            added_by=added_by,
        )
        self._entries.append(entry)
        self._save_metadata()
        self._regenerate_edl_files()
        logger.info(f"EDL entry added: {value} (TTL: {entry.ttl_days} days)")
        return True

    def remove_entry(self, value: str) -> bool:
        """移除一筆 EDL entry"""
        before = len(self._entries)
        self._entries = [e for e in self._entries if e.value != value]
        if len(self._entries) < before:
            self._save_metadata()
            self._regenerate_edl_files()
            logger.info(f"EDL entry removed: {value}")
            return True
        return False

    def cleanup_expired(self) -> int:
        """清理過期 entries，回傳移除數量"""
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
        """列出所有有效 entries"""
        return [e.to_dict() for e in self._entries if not e.is_expired]
