"""
Graylog Client

封裝 Graylog Search API 存取邏輯，供 EnrichmentService 使用。
獨立成模組方便未來擴展與單獨 debug。
"""

import json
import logging
import math
import time

import httpx

logger = logging.getLogger(__name__)

_HISTOGRAM_CACHE_TTL = 3600  # seconds
_HISTOGRAM_LOOKBACK_DAYS = 14


class GraylogClient:
    def __init__(self, config: dict):
        graylog_cfg = config.get("graylog", {})
        self.api_url = graylog_cfg.get("api_url", "")
        self.api_token = graylog_cfg.get("api_token", "")
        self.lookback_hours = graylog_cfg.get("lookback_hours", 24)
        # cache: key → (expires_at, daily_counts)
        self._histogram_cache: dict[str, tuple[float, list[int]]] = {}

    @property
    def enabled(self) -> bool:
        return bool(self.api_url and self.api_token)

    async def query_frequency(
        self, source_ip: str, destination_ip: str, threat_id: str
    ) -> dict:
        """查詢同一來源/目標在過去 lookback_hours 內的事件頻率，並附帶 z-score 或 ratio 統計。"""
        if not self.enabled:
            return _disabled_result()

        sig_id = self._extract_signature_id(threat_id)
        sig_query = f'alert_signature:*{sig_id}*'

        try:
            same_src_same_sig, same_src_other_sig, same_dst_same_sig = (
                await self._count(f'source_ip:"{source_ip}" AND {sig_query}'),
                await self._count(f'source_ip:"{source_ip}" AND NOT {sig_query}'),
                await self._count(f'destination_ip:"{destination_ip}" AND {sig_query}'),
            )
        except Exception as e:
            logger.error(f"Graylog frequency query failed: {e}", exc_info=True)
            return _disabled_result()

        base = {
            "same_src_same_sig_24h": same_src_same_sig,
            "same_src_other_sig_24h": same_src_other_sig,
            "same_dst_same_sig_24h": same_dst_same_sig,
        }

        # ── 主路徑：Views API z-score ────────────────────────────────────────
        hist_query = f'source_ip:"{source_ip}" AND {sig_query}'
        daily = await self._histogram_cached(hist_query)
        if daily and len(daily) >= 3:
            # 排除最後一筆（今日未完整的 bucket）
            baseline = daily[:-1]
            n = len(baseline)
            mu = sum(baseline) / n
            sigma = math.sqrt(sum((x - mu) ** 2 for x in baseline) / n)
            z = (same_src_same_sig - mu) / (sigma + 1e-9)
            return {
                **base,
                "z_score": round(z, 2),
                "daily_avg": round(mu, 1),
                "ratio": None,
                "freq_method": "z_score",
            }

        # ── Fallback：7d ratio ───────────────────────────────────────────────
        try:
            count_7d = await self._count(hist_query, range_sec=7 * 24 * 3600)
            daily_avg_7d = count_7d / 7
            ratio = same_src_same_sig / (daily_avg_7d + 1)
            return {
                **base,
                "z_score": None,
                "daily_avg": round(daily_avg_7d, 1),
                "ratio": round(ratio, 2),
                "freq_method": "ratio",
            }
        except Exception as e:
            logger.warning(f"Graylog 7d fallback failed: {e}")

        return {**base, "z_score": None, "daily_avg": None, "ratio": None, "freq_method": "count_only"}

    # ── 內部方法 ──────────────────────────────────────────────────────────────

    async def _histogram_cached(self, query: str) -> list[int] | None:
        """取得每日計數列表，結果 cache 1 小時。"""
        now = time.monotonic()
        entry = self._histogram_cache.get(query)
        if entry and entry[0] > now:
            return entry[1]

        daily = await self._histogram(query)
        if daily:
            self._histogram_cache[query] = (now + _HISTOGRAM_CACHE_TTL, daily)
        return daily

    async def _histogram(self, query: str) -> list[int] | None:
        """呼叫 POST /views/search/sync 取得每日計數。失敗回傳 None。"""
        range_sec = _HISTOGRAM_LOOKBACK_DAYS * 24 * 3600
        body = {
            "queries": [{
                "id": "q1",
                "query": {"type": "elasticsearch", "query_string": query},
                "timerange": {"type": "relative", "range": range_sec},
                "search_types": [{
                    "id": "st1",
                    "type": "pivot",
                    "row_groups": [{
                        "type": "time",
                        "field": "timestamp",
                        "interval": {"type": "timeunit", "timeunit": "1d"},
                    }],
                    "column_groups": [],
                    "series": [{"type": "count", "id": "count()"}],
                    "rollup": True,
                    "filter": None,
                    "streams": [],
                }],
            }]
        }
        try:
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.post(
                    f"{self.api_url}/views/search/sync",
                    content=json.dumps(body),
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "X-Requested-By": "cli",
                    },
                    auth=(self.api_token, "token"),
                    timeout=60,
                )
        except Exception as e:
            logger.warning(f"Graylog histogram request failed: {e}")
            return None

        if resp.status_code != 200 or not resp.text.strip():
            logger.warning(f"Graylog histogram HTTP {resp.status_code}")
            return None

        try:
            data, _ = json.JSONDecoder().raw_decode(resp.text.strip())
            rows = data["results"]["q1"]["search_types"]["st1"]["rows"]
        except Exception as e:
            logger.warning(f"Graylog histogram parse error: {e}")
            return None

        counts = []
        for row in rows:
            if row.get("source") == "non-leaf":
                continue
            for val in row.get("values", []):
                if val.get("key") == ["count()"]:
                    counts.append(int(val.get("value") or 0))
                    break

        return counts if len(counts) >= 3 else None

    async def _count(self, query: str, range_sec: int | None = None) -> int:
        """呼叫 /search/universal/relative 計算符合條件的事件數"""
        if range_sec is None:
            range_sec = self.lookback_hours * 3600
        logger.debug(f"Graylog query: {query!r}")
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(
                f"{self.api_url}/search/universal/relative",
                params={
                    "query": query,
                    "range": range_sec,
                    "limit": 1,
                    "fields": "timestamp",
                },
                headers={"Accept": "application/json"},
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


def _disabled_result() -> dict:
    return {
        "same_src_same_sig_24h": -1,
        "same_src_other_sig_24h": -1,
        "same_dst_same_sig_24h": -1,
        "z_score": None,
        "daily_avg": None,
        "ratio": None,
        "freq_method": "disabled",
    }
