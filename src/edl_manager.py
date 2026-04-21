"""
EDL (External Dynamic List) Manager

管理 PA 防火牆用的 EDL 檔案，支援：
- 新增 entry（IP / URL / Domain）
- TTL 自動過期移除
- 產生純文字 EDL 檔案供 PA 拉取
"""

import json
import logging
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


class EDLManager:
    def __init__(self, config: dict):
        edl_cfg = config.get("edl", {})
        self.output_dir = Path(edl_cfg.get("output_dir", "/var/www/edl"))
        self.default_ttl_days = edl_cfg.get("default_ttl_days", 30)
        self.metadata_path = self.output_dir / "edl_metadata.json"

        # EDL 檔案路徑（PA 會拉取這些）
        self.edl_files = {
            "ip": self.output_dir / "block_ip.txt",
            "url": self.output_dir / "block_url.txt",
            "domain": self.output_dir / "block_domain.txt",
        }

        self._entries: list[EDLEntry] = []
        self._load_metadata()

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

    def _regenerate_edl_files(self):
        """從 metadata 重新產生純文字 EDL 檔案"""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # 依類型分類
        ips, urls, domains = [], [], []
        for entry in self._entries:
            if entry.is_expired:
                continue
            v = entry.value
            if v.startswith("http://") or v.startswith("https://"):
                urls.append(v)
            elif "." in v and not any(c == "/" for c in v):
                # 簡易判斷：有 . 但沒有 / → 可能是 IP 或 domain
                # 進一步判斷是否為 IP
                parts = v.split(".")
                if all(p.isdigit() for p in parts):
                    ips.append(v)
                else:
                    domains.append(v)
            else:
                ips.append(v)  # 預設當 IP

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

    def suggest_entry(self, value: str, source_event: dict | None = None):
        """
        建議新增一筆 EDL entry。
        目前僅記錄到 pending 清單，需人工確認後才正式加入。
        """
        # TODO Phase 3: 實作 pending 佇列 + 確認機制
        logger.info(f"EDL suggestion: {value} (from event: {source_event.get('event_uid', 'unknown') if source_event else 'manual'})")

    def add_entry(
        self,
        value: str,
        ttl_days: int | None = None,
        source_signature: str = "",
        source_event_id: str = "",
        added_by: str = "auto",
    ) -> bool:
        """正式新增一筆 EDL entry"""
        # 檢查是否已存在
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
