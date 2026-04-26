"""
BlacklistBackend — Gate 2 可插拔黑名單介面

目前實作：CustomListBackend（純文字 IP/CIDR 檔案）
未來可插拔：AbuseIPDB、FireHOL、threat intel feeds 等
"""

from abc import ABC, abstractmethod


class BlacklistBackend(ABC):
    @abstractmethod
    async def check(self, src_ip: str, dst_ip: str) -> str | None:
        """命中 → 返回理由字串；未命中 → None"""
        ...

    @abstractmethod
    async def reload(self) -> None:
        """熱重載資料來源"""
        ...

    @property
    @abstractmethod
    def stats(self) -> dict:
        """回傳統計資訊 dict"""
        ...
