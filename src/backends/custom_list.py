"""
CustomListBackend — Gate 2 黑名單：純文字 IP/CIDR 檔案

格式：每行一個 IP 位址或 CIDR 網段，`#` 開頭為注解，空行忽略。
支援熱重載（POST /blacklist/reload）。
"""

import asyncio
import ipaddress
import logging
from datetime import datetime, timezone
from pathlib import Path

from ..blacklist_backend import BlacklistBackend

logger = logging.getLogger(__name__)


class CustomListBackend(BlacklistBackend):
    def __init__(self, list_path: str):
        self._path = Path(list_path)
        self._lock = asyncio.Lock()
        self._entries: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._loaded_at: datetime | None = None
        self._hit_count: int = 0
        self._load()

    def _load(self) -> None:
        entries = []
        try:
            for line in self._path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    entries.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    logger.warning(f"Blacklist: invalid entry ignored: {line!r}")
        except FileNotFoundError:
            logger.warning(f"Blacklist file not found: {self._path}")
        self._entries = entries
        self._loaded_at = datetime.now(timezone.utc)
        logger.info(f"Blacklist loaded: {len(self._entries)} entries from {self._path}")

    async def check(self, src_ip: str, dst_ip: str) -> str | None:
        async with self._lock:
            if not src_ip:
                return None
            try:
                addr = ipaddress.ip_address(src_ip)
            except ValueError:
                return None
            for net in self._entries:
                if addr in net:
                    self._hit_count += 1
                    return f"Source IP {src_ip} 符合黑名單 {net}"
        return None

    async def reload(self) -> None:
        async with self._lock:
            self._load()

    @property
    def stats(self) -> dict:
        return {
            "entry_count": len(self._entries),
            "hit_count": self._hit_count,
            "loaded_at": self._loaded_at.isoformat() if self._loaded_at else None,
            "path": str(self._path),
        }
