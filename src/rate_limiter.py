"""
Rate Limiter

以 TTLCache 實作去重快取，防止相同特徵的日誌在短時間內
重複觸發 LLM API 呼叫與 Email 告警。

使用 threading.Lock（非 asyncio.Lock）確保跨 event loop 呼叫安全。
"""

import threading

from cachetools import TTLCache


class RateLimiter:
    def __init__(self, window_seconds: int = 900, maxsize: int = 10_000):
        self._cache: TTLCache = TTLCache(maxsize=maxsize, ttl=window_seconds)
        self._lock = threading.Lock()

    def check_and_record(self, src_ip: str, sig_id: str) -> tuple[bool, int]:
        """
        檢查是否為重複事件並計數。
        第一次出現回傳 (False, 1)；後續重複回傳 (True, n)。
        """
        key = (src_ip, sig_id)
        with self._lock:
            if key in self._cache:
                self._cache[key] += 1
                return True, self._cache[key]
            self._cache[key] = 1
            return False, 1

    def current_count(self, src_ip: str, sig_id: str) -> int:
        with self._lock:
            return self._cache.get((src_ip, sig_id), 0)
