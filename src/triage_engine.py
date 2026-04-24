"""
Triage Engine

串接各 Gate 的研判主流程：
  Rate Limit → Gate 1（動態白名單）→ Gate 2（黑名單，Phase 3）→ Gate 3（規則 + LLM）
"""

import logging

from .known_fp import KnownFPChecker
from .llm_client import LLMClient, TriageVerdict
from .rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class TriageEngine:
    def __init__(self, config: dict):
        rl_cfg = config.get("rate_limit", {})
        self.rate_limiter = RateLimiter(
            window_seconds=rl_cfg.get("window_seconds", 900),
            maxsize=rl_cfg.get("maxsize", 10_000),
        )
        fp_csv = config.get("known_fp", {}).get("csv_path", "config/known_fp.csv")
        self.known_fp = KnownFPChecker(fp_csv)
        self.llm = LLMClient(config)

    async def triage(self, enriched: dict) -> TriageVerdict:
        """
        執行完整研判流程。
        Rate Limit → Gate 1 → Gate 2（待 Phase 3）→ Gate 3
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
            )

        # Gate 1：已知誤判白名單
        fp_note = self.known_fp.check(summary)
        if fp_note:
            return TriageVerdict(
                verdict="false_positive",
                confidence="high",
                reasoning=f"符合 known_fp 規則：{fp_note}",
                recommended_action="suppress",
            )

        # Gate 2：開源黑名單（Phase 3 實作，目前 pass-through）

        # Gate 3：固定規則 + LLM
        return await self.llm.triage_gate3(enriched)
