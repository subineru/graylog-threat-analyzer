"""
Graylog Client

封裝 Graylog Search API 存取邏輯，供 EnrichmentService 使用。
獨立成模組方便未來擴展與單獨 debug。
"""

import logging

import httpx

logger = logging.getLogger(__name__)


class GraylogClient:
    def __init__(self, config: dict):
        graylog_cfg = config.get("graylog", {})
        self.api_url = graylog_cfg.get("api_url", "")
        self.api_token = graylog_cfg.get("api_token", "")
        self.lookback_hours = graylog_cfg.get("lookback_hours", 24)

    @property
    def enabled(self) -> bool:
        return bool(self.api_url and self.api_token)

    async def query_frequency(
        self, source_ip: str, destination_ip: str, threat_id: str
    ) -> dict:
        """查詢同一來源/目標在過去 lookback_hours 內的事件頻率"""
        if not self.enabled:
            return {
                "same_src_same_sig_24h": -1,
                "same_src_other_sig_24h": -1,
                "same_dst_same_sig_24h": -1,
            }

        if "(" in threat_id:
            sig_query = f'alert_signature:"{threat_id}"'
        else:
            sig_id = self._extract_signature_id(threat_id)
            sig_query = f'alert_signature:*{sig_id}*'

        try:
            async with httpx.AsyncClient(verify=False) as client:
                same_src_same_sig = await self._count(
                    client, f'source_ip:"{source_ip}" AND {sig_query}'
                )
                same_src_other_sig = await self._count(
                    client, f'source_ip:"{source_ip}" AND NOT {sig_query}'
                )
                same_dst_same_sig = await self._count(
                    client, f'destination_ip:"{destination_ip}" AND {sig_query}'
                )
            return {
                "same_src_same_sig_24h": same_src_same_sig,
                "same_src_other_sig_24h": same_src_other_sig,
                "same_dst_same_sig_24h": same_dst_same_sig,
            }
        except Exception as e:
            logger.error(f"Graylog frequency query failed: {e}", exc_info=True)
            return {
                "same_src_same_sig_24h": -1,
                "same_src_other_sig_24h": -1,
                "same_dst_same_sig_24h": -1,
            }

    async def _count(self, client: httpx.AsyncClient, query: str) -> int:
        """呼叫 /search/universal/relative 計算符合條件的事件數"""
        logger.debug(f"Graylog query: {query!r}")
        resp = await client.get(
            f"{self.api_url}/search/universal/relative",
            params={
                "query": query,
                "range": self.lookback_hours * 3600,
                "limit": 0,
                "fields": "timestamp",
            },
            auth=(self.api_token, "token"),
            timeout=10,
        )
        if not resp.text:
            logger.error(
                f"Graylog returned empty body (HTTP {resp.status_code}) "
                f"query={query!r}"
            )
            raise ValueError(f"Empty response from Graylog (HTTP {resp.status_code})")
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError:
            logger.error(
                f"Graylog HTTP error {resp.status_code}: {resp.text[:300]}"
            )
            raise
        return resp.json().get("total_results", 0)

    @staticmethod
    def _extract_signature_id(signature: str) -> str:
        """從 'Microsoft Windows NTLMSSP Detection(92322)' 提取 '92322'"""
        if "(" in signature and signature.endswith(")"):
            return signature.rsplit("(", 1)[-1].rstrip(")")
        return signature
