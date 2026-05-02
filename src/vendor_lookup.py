"""
Vendor Lookup

從 vendors.csv 載入供應商 IP / CIDR 清單，提供 IP 比對查詢。
支援精確 IP 與 CIDR 網段，查詢失敗不拋出例外。
"""

import csv
import ipaddress
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class VendorLookup:
    def __init__(self, csv_path: str):
        self._entries: list[dict] = []
        self._load(csv_path)

    def _load(self, csv_path: str) -> None:
        path = Path(csv_path)
        if not path.exists():
            logger.info(f"Vendor CSV not found: {csv_path} (vendor lookup disabled)")
            return
        with open(path, encoding="utf-8") as f:
            lines = [line for line in f if not line.startswith("#")]
        for row in csv.DictReader(lines):
            cidr = row.get("ip_or_cidr", "").strip()
            if not cidr:
                continue
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                self._entries.append({
                    "network":         network,
                    "vendor_name":     row.get("vendor_name", "").strip(),
                    "allowed_service": row.get("allowed_service", "any").strip().lower(),
                    "destination_ip":  row.get("destination_ip", "").strip(),
                    "note":            row.get("note", "").strip(),
                })
            except ValueError:
                logger.warning(f"Invalid IP/CIDR in vendors.csv: {cidr!r}")
        logger.info(f"Loaded {len(self._entries)} vendor entries from {csv_path}")

    def lookup(self, ip: str) -> dict | None:
        """回傳第一筆匹配的供應商資訊，無匹配回傳 None。"""
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for entry in self._entries:
            if addr in entry["network"]:
                return {
                    "vendor_name":     entry["vendor_name"],
                    "allowed_service": entry["allowed_service"],
                    "destination_ip":  entry["destination_ip"],
                    "note":            entry["note"],
                }
        return None
