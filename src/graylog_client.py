"""
Graylog Client

封裝 Graylog Search API 存取邏輯，供 EnrichmentService 使用。
獨立成模組方便未來擴展與單獨 debug。
"""

import json
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

        # 一律用 signature ID 做 wildcard 查詢，避免完整格式中括弧的 Lucene 解析問題
        sig_id = self._extract_signature_id(threat_id)
        sig_query = f'alert_signature:*{sig_id}*'

        try:
            # 每個 _count 使用獨立 AsyncClient，避免 keep-alive 連線複用
            # 導致前一個 response 的殘留 bytes 混入下一個 response 的問題
            same_src_same_sig = await self._count(
                f'source_ip:"{source_ip}" AND {sig_query}'
            )
            same_src_other_sig = await self._count(
                f'source_ip:"{source_ip}" AND NOT {sig_query}'
            )
            same_dst_same_sig = await self._count(
                f'destination_ip:"{destination_ip}" AND {sig_query}'
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

    async def _count(self, query: str) -> int:
        """呼叫 /search/universal/relative 計算符合條件的事件數"""
        logger.debug(f"Graylog query: {query!r}")
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(
                f"{self.api_url}/search/universal/relative",
                params={
                    "query": query,
                    "range": self.lookback_hours * 3600,
                    "limit": 1,
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
            logger.error(f"Graylog HTTP error {resp.status_code}: {resp.text[:300]}")
            raise

        # 使用 raw_decode 只解析第一個完整 JSON 物件，
        # 避免 response 末尾有殘留 bytes 時拋出 Extra data 錯誤
        try:
            data, _ = json.JSONDecoder().raw_decode(resp.text.strip())
            return data.get("total_results", 0)
        except json.JSONDecodeError:
            logger.error(f"Graylog JSON parse error, raw response: {resp.text[:300]}")
            raise

    @staticmethod
    def _extract_signature_id(signature: str) -> str:
        """從 'Microsoft Windows NTLMSSP Detection(92322)' 提取 '92322'"""
        if "(" in signature and signature.endswith(")"):
            return signature.rsplit("(", 1)[-1].rstrip(")")
        return signature
