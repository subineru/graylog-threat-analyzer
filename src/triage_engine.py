"""
Triage Engine

串接各 Gate 的研判主流程：
  Rate Limit → Gate 1（動態白名單）→ Gate 2（黑名單，Phase 3）→ Gate 3（規則 + LLM）
"""

import logging

from .blacklist_backend import BlacklistBackend
from .backends.custom_list import CustomListBackend
from .llm_client import LLMClient, TriageVerdict
from .rate_limiter import RateLimiter
from .whitelist_manager import WhitelistManager

logger = logging.getLogger(__name__)


class TriageEngine:
    def __init__(self, config: dict):
        rl_cfg = config.get("rate_limit", {})
        self.rate_limiter = RateLimiter(
            window_seconds=rl_cfg.get("window_seconds", 900),
            maxsize=rl_cfg.get("maxsize", 10_000),
        )
        # Support both "whitelist" (new) and "known_fp" (legacy) config keys
        wl_cfg = config.get("whitelist") or config.get("known_fp", {})
        fp_csv = wl_cfg.get("csv_path", "config/known_fp.csv")
        default_ttl = wl_cfg.get("default_ttl_days", 90)
        sweep_interval = wl_cfg.get("sweep_interval_seconds", 300)
        self.whitelist = WhitelistManager(fp_csv, default_ttl_days=default_ttl, sweep_interval=sweep_interval)
        self.llm = LLMClient(config)

        bl_cfg = config.get("blacklist", {})
        self.blacklist: BlacklistBackend | None = None
        if bl_cfg.get("enabled", False):
            self.blacklist = CustomListBackend(
                bl_cfg.get("custom_list_path", "config/custom_blacklist.txt")
            )

    async def triage(self, enriched: dict) -> TriageVerdict:
        """
        執行完整研判流程。
        Rate Limit → Gate 1 (whitelist) → Gate 2 (blacklist) → Gate 3
        """
        summary = enriched.get("event_summary", {})
        src_ip = summary.get("source_ip", "")
        sig_id = summary.get("signature_id", "") or summary.get("signature_name", "")

        # Rate Limit：同一 src_ip + sig_id 在視窗內重複出現，直接抑制
        is_dup, count = self.rate_limiter.check_and_record(src_ip, sig_id)
        if is_dup:
            logger.debug(f"Rate limited: src={src_ip} sig={sig_id} count={count}")
            return TriageVerdict(
                verdict="duplicate",
                confidence="high",
                reasoning=f"同一來源 + Signature 在時間視窗內已處理，已抑制（累計 {count} 次）。",
                recommended_action="suppress",
                stage="rate_limit",
            )

        # Gate 1：動態白名單（async，更新 hit_count / last_hit_time）
        fp_note = await self.whitelist.check(summary)
        if fp_note:
            return TriageVerdict(
                verdict="false_positive",
                confidence="high",
                reasoning=f"符合白名單規則：{fp_note}",
                recommended_action="suppress",
                stage="whitelist",
            )

        # Gate 2：自訂黑名單（disabled by default；config.blacklist.enabled: true 啟用）
        if self.blacklist:
            dst_ip = summary.get("destination_ip", "")
            bl_note = await self.blacklist.check(src_ip, dst_ip)
            if bl_note:
                logger.info(f"Blacklist hit: {bl_note}")
                return TriageVerdict(
                    verdict="anomalous",
                    confidence="high",
                    reasoning=f"來源 IP 命中黑名單：{bl_note}",
                    recommended_action="block",
                    stage="blacklist",
                )

        # Gate 3：固定規則 + LLM
        return await self.llm.triage_gate3(enriched)
