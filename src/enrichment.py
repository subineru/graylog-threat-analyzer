"""
Context Enrichment Service

負責為單一 THREAT 事件補充上下文資訊：
1. 資產清冊查詢（IP → hostname, role, department）
2. Graylog API 查詢（同 source/destination 的歷史事件頻率）
3. 威脅情資查詢（外部 IP 的信譽評分）
"""

import asyncio
import csv
import logging
import socket
from pathlib import Path

from .graylog_client import GraylogClient
from .normalizers.pan_threat import normalize
from .vendor_lookup import VendorLookup

logger = logging.getLogger(__name__)


class AssetLookup:
    """從 CSV 載入資產清冊，提供 IP → 資產資訊查詢"""

    def __init__(self, csv_path: str):
        self._assets: dict[str, dict] = {}
        self._load(csv_path)

    def _load(self, csv_path: str):
        path = Path(csv_path)
        if not path.exists():
            logger.warning(f"Asset CSV not found: {csv_path}")
            return
        with open(path, "r", encoding="utf-8") as f:
            # Skip comment lines before passing to DictReader
            lines = [line for line in f if not line.startswith("#")]
        reader = csv.DictReader(lines)
        for row in reader:
            self._assets[row["ip"]] = {
                "hostname": row.get("hostname", "unknown"),
                "role": row.get("role", "unknown"),
                "department": row.get("department", "unknown"),
                "note": row.get("note", ""),
            }
        logger.info(f"Loaded {len(self._assets)} assets from {csv_path}")

    def lookup(self, ip: str) -> dict:
        return self._assets.get(ip, {
            "hostname": "unknown",
            "role": "unknown",
            "department": "unknown",
            "note": "",
        })


class EnrichmentService:
    def __init__(self, config: dict):
        self.config = config
        asset_csv = config.get("assets", {}).get("csv_path", "config/assets.csv")
        vendor_csv = config.get("vendors", {}).get("csv_path", "config/vendors.csv")
        self.asset_lookup = AssetLookup(asset_csv)
        self.vendor_lookup = VendorLookup(vendor_csv)
        self.graylog = GraylogClient(config)

    async def enrich(self, message: dict) -> dict:
        """對單一事件進行完整 enrichment"""
        message = normalize(message)
        source_ip = message.get("source_ip", "")
        destination_ip = message.get("destination_ip", "")
        threat_id = message.get("threat_id", "") or message.get("alert_signature", "")
        # signature_name 目前通常為空（JMTE template 尚未加入），fallback 到 threat_id
        sig_name = message.get("signature_name", "") or f"ThreatID {threat_id}"

        # 1. 資產查詢
        source_asset = self.asset_lookup.lookup(source_ip)
        destination_asset = self.asset_lookup.lookup(destination_ip)

        # 1a. DNS PTR 補充（僅限內部未知主機，timeout 2s）
        if source_asset["hostname"] == "unknown" and self._is_internal(source_ip):
            source_asset = {**source_asset, "hostname": await self._ptr_lookup(source_ip)}
        if destination_asset["hostname"] == "unknown" and self._is_internal(destination_ip):
            destination_asset = {**destination_asset, "hostname": await self._ptr_lookup(destination_ip)}

        # 1b. 供應商查詢（外部 IP）
        vendor_info = self.vendor_lookup.lookup(source_ip) if not self._is_internal(source_ip) else None

        # 2. 頻率查詢
        frequency = await self.graylog.query_frequency(source_ip, destination_ip, threat_id)

        # 3. 威脅情資（僅外部 IP）
        source_reputation = await self._check_reputation(source_ip)
        dest_reputation = await self._check_reputation(destination_ip)

        return {
            "event_summary": {
                "signature_id": threat_id,
                "signature_name": sig_name,
                "severity": message.get("severity") or message.get("vendor_alert_severity", "unknown"),
                "action": message.get("vendor_event_action", "unknown"),
                "source_ip": source_ip,
                "source_user": message.get("source_user_name", ""),
                "destination_ip": destination_ip,
                "destination_user": message.get("destination_user_name", ""),
                "protocol": f"{message.get('application_name', '')} / {message.get('network_transport', '')}".strip(" /"),
                "direction": message.get("pan_alert_direction", ""),
                "zone_flow": f"{message.get('source_zone', '')} → {message.get('destination_zone', '')}",
                "rule_name": message.get("rule_name", ""),
                "rcvss": message.get("RCVSS", ""),
                "threat_content_type": message.get("threat_content_type", ""),
                "file_name": message.get("file_name", ""),
                "destination_port": message.get("destination_port", ""),
                "firewall": message.get("firewall", ""),
            },
            "asset_context": {
                "source_asset": source_asset,
                "destination_asset": destination_asset,
                "vendor_info": vendor_info,
            },
            "frequency_context": frequency,
            "threat_intel": {
                "source_ip_reputation": source_reputation,
                "destination_ip_reputation": dest_reputation,
            },
            "raw_message": message,
        }

    async def _ptr_lookup(self, ip: str) -> str:
        """DNS PTR 反解（僅用於補充內部未知主機名）。查詢失敗回傳 'unknown'。"""
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=2.0,
            )
            return result[0]
        except Exception:
            return "unknown"

    async def _check_reputation(self, ip: str) -> str:
        """查詢外部威脅情資（僅限非 RFC1918 IP）"""
        if self._is_internal(ip):
            return "N/A (internal)"

        # TODO: 接入 AbuseIPDB 或 OTX API
        return "not_checked"

    @staticmethod
    def _is_internal(ip: str) -> bool:
        """判斷是否為 RFC1918 內部 IP 或保留地址"""
        if not ip or ip == "0.0.0.0":
            return True
        if ip.startswith("10.") or ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            parts = ip.split(".")
            try:
                return 16 <= int(parts[1]) <= 31
            except (IndexError, ValueError):
                return False
        return False
