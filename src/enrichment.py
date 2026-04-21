"""
Context Enrichment Service

負責為單一 THREAT 事件補充上下文資訊：
1. 資產清冊查詢（IP → hostname, role, department）
2. Graylog API 查詢（同 source/destination 的歷史事件頻率）
3. 威脅情資查詢（外部 IP 的信譽評分）
"""

import csv
import logging
from pathlib import Path

import httpx

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
            reader = csv.DictReader(f)
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
        self.asset_lookup = AssetLookup(asset_csv)

        graylog_cfg = config.get("graylog", {})
        self.graylog_api_url = graylog_cfg.get("api_url", "")
        self.graylog_api_token = graylog_cfg.get("api_token", "")
        self.lookback_hours = graylog_cfg.get("lookback_hours", 24)

    async def enrich(self, message: dict) -> dict:
        """對單一事件進行完整 enrichment"""
        source_ip = message.get("source_ip", "")
        destination_ip = message.get("destination_ip", "")
        signature = message.get("alert_signature", "")

        # 1. 資產查詢
        source_asset = self.asset_lookup.lookup(source_ip)
        destination_asset = self.asset_lookup.lookup(destination_ip)

        # 2. 頻率查詢
        frequency = await self._query_frequency(source_ip, destination_ip, signature)

        # 3. 威脅情資（僅外部 IP）
        source_reputation = await self._check_reputation(source_ip)
        dest_reputation = await self._check_reputation(destination_ip)

        return {
            "event_summary": {
                "signature_id": self._extract_signature_id(signature),
                "signature_name": signature,
                "severity": message.get("vendor_alert_severity", "unknown"),
                "action": message.get("vendor_event_action", "unknown"),
                "source_ip": source_ip,
                "source_user": message.get("source_user_name", ""),
                "destination_ip": destination_ip,
                "destination_user": message.get("destination_user_name", ""),
                "protocol": f"{message.get('application_name', '')} / {message.get('network_transport', '')}",
                "direction": message.get("pan_alert_direction", ""),
                "zone_flow": f"{message.get('source_zone', '')} → {message.get('destination_zone', '')}",
                "rule_name": message.get("rule_name", ""),
                "rcvss": message.get("RCVSS", ""),
            },
            "asset_context": {
                "source_asset": source_asset,
                "destination_asset": destination_asset,
            },
            "frequency_context": frequency,
            "threat_intel": {
                "source_ip_reputation": source_reputation,
                "destination_ip_reputation": dest_reputation,
            },
            "raw_message": message,
        }

    async def _query_frequency(
        self, source_ip: str, destination_ip: str, signature: str
    ) -> dict:
        """查詢 Graylog API 取得歷史頻率"""
        if not self.graylog_api_url:
            return {
                "same_src_same_sig_24h": -1,
                "same_src_other_sig_24h": -1,
                "same_dst_same_sig_24h": -1,
            }

        sig_id = self._extract_signature_id(signature)

        try:
            async with httpx.AsyncClient(verify=False) as client:
                # 同 source IP + 同 signature
                same_src_same_sig = await self._graylog_count(
                    client,
                    f'source_ip:"{source_ip}" AND alert_signature:"{sig_id}"',
                )
                # 同 source IP + 其他 signature
                same_src_other_sig = await self._graylog_count(
                    client,
                    f'source_ip:"{source_ip}" AND NOT alert_signature:"{sig_id}" AND event_log_name:"THREAT"',
                )
                # 同 destination IP + 同 signature
                same_dst_same_sig = await self._graylog_count(
                    client,
                    f'destination_ip:"{destination_ip}" AND alert_signature:"{sig_id}"',
                )

            return {
                "same_src_same_sig_24h": same_src_same_sig,
                "same_src_other_sig_24h": same_src_other_sig,
                "same_dst_same_sig_24h": same_dst_same_sig,
            }
        except Exception as e:
            logger.error(f"Graylog frequency query failed: {e}")
            return {
                "same_src_same_sig_24h": -1,
                "same_src_other_sig_24h": -1,
                "same_dst_same_sig_24h": -1,
            }

    async def _graylog_count(self, client: httpx.AsyncClient, query: str) -> int:
        """呼叫 Graylog Search API 計算事件數量"""
        resp = await client.get(
            f"{self.graylog_api_url}/search/universal/relative",
            params={
                "query": query,
                "range": self.lookback_hours * 3600,
                "limit": 0,
                "fields": "timestamp",
            },
            auth=(self.graylog_api_token, "token"),
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("total_results", 0)

    async def _check_reputation(self, ip: str) -> str:
        """查詢外部威脅情資（僅限非 RFC1918 IP）"""
        if self._is_internal(ip):
            return "N/A (internal)"

        # TODO: 接入 AbuseIPDB 或 OTX API
        return "not_checked"

    @staticmethod
    def _is_internal(ip: str) -> bool:
        """簡易判斷是否為內部 IP"""
        return (
            ip.startswith("192.168.")
            or ip.startswith("10.")
            or ip.startswith("172.16.")
            or ip == "0.0.0.0"
        )

    @staticmethod
    def _extract_signature_id(signature: str) -> str:
        """從 'Microsoft Windows NTLMSSP Detection(92322)' 提取 '92322'"""
        if "(" in signature and signature.endswith(")"):
            return signature.rsplit("(", 1)[-1].rstrip(")")
        return signature
