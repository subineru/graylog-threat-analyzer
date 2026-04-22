"""
LLM Client

封裝內部 LLM API 呼叫邏輯。
Phase 1 使用固定規則（不呼叫 LLM），Phase 2 切換到 LLM 研判。
"""

import json
import logging
import re
from pathlib import Path

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class TriageVerdict(BaseModel):
    verdict: str  # normal | false_positive | anomalous
    confidence: str  # high | medium | low
    reasoning: str
    recommended_action: str  # suppress | monitor | block
    edl_entry: str | None = None


class LLMClient:
    def __init__(self, config: dict):
        llm_cfg = config.get("llm", {})
        self.api_url = llm_cfg.get("api_url", "")
        self.model = llm_cfg.get("model", "")
        self.temperature = llm_cfg.get("temperature", 0.1)
        self.max_tokens = llm_cfg.get("max_tokens", 500)
        self.timeout = llm_cfg.get("timeout", 30)
        self.api_key = llm_cfg.get("api_key", "")
        self.use_llm = bool(self.api_url and self.model)

        # 載入 prompt template
        prompt_path = Path("prompts/triage.md")
        if prompt_path.exists():
            self.prompt_template = prompt_path.read_text(encoding="utf-8")
        else:
            self.prompt_template = ""
            logger.warning("Prompt template not found at prompts/triage.md")

    async def triage(self, enriched: dict) -> TriageVerdict:
        """
        研判單一事件。
        Phase 1: 使用固定規則。
        Phase 2: 呼叫 LLM。
        """
        if not self.use_llm:
            return self._rule_based_triage(enriched)

        return await self._llm_triage(enriched)

    def _rule_based_triage(self, enriched: dict) -> TriageVerdict:
        """
        Phase 1 固定規則研判。
        規則優先順序由上到下，命中第一條即回傳。
        """
        summary = enriched.get("event_summary", {})
        asset = enriched.get("asset_context", {})
        freq = enriched.get("frequency_context", {})

        action = summary.get("action", "")
        severity = summary.get("severity", "")
        source_ip = summary.get("source_ip", "")
        sig_name = summary.get("signature_name", "")

        src_asset = asset.get("source_asset", {})
        dst_asset = asset.get("destination_asset", {})
        src_role = src_asset.get("role", "unknown")
        dst_role = dst_asset.get("role", "unknown")
        src_known = src_asset.get("hostname", "unknown") != "unknown"

        # 規則 1: PA 已阻擋的外部攻擊 → 已防禦的已知攻擊
        if action in ("drop", "block-ip", "reset-both") and not self._is_internal(source_ip):
            return TriageVerdict(
                verdict="false_positive",
                confidence="high",
                reasoning=f"PA 已阻擋 (action={action})，來源為外部 IP，屬已防禦的已知攻擊。",
                recommended_action="suppress",
            )

        # 規則 2: informational + alert → 偵測型規則，正常行為
        if severity == "informational" and action == "alert":
            return TriageVerdict(
                verdict="normal",
                confidence="medium",
                reasoning="Severity 為 informational，PA 僅 alert 未阻擋，大多為正常偵測。",
                recommended_action="monitor",
            )

        # 規則 3: 已知端點對 AD 發起 NTLMSSP → Windows 正常認證
        if (
            src_role == "user-endpoint"
            and dst_role == "domain-controller"
            and "NTLMSSP" in sig_name
        ):
            return TriageVerdict(
                verdict="normal",
                confidence="high",
                reasoning=f"已知 user-endpoint ({src_asset.get('hostname')}) 對 AD 網域控制站進行 NTLMSSP 認證，為正常 Windows 認證流程。",
                recommended_action="suppress",
            )

        # 規則 4: 未知外部 IP（不在資產清冊 + 非 RFC1918）→ 高風險異常
        if not src_known and not self._is_internal(source_ip):
            return TriageVerdict(
                verdict="anomalous",
                confidence="high",
                reasoning=f"來源 IP {source_ip} 不在資產清冊中且為外部 IP，屬未知外部裝置，建議封鎖。",
                recommended_action="block",
                edl_entry=source_ip,
            )

        # 規則 5: 未知內部 IP（不在資產清冊 + RFC1918）→ 疑似未授權設備
        if not src_known and self._is_internal(source_ip):
            return TriageVerdict(
                verdict="anomalous",
                confidence="medium",
                reasoning=f"來源 IP {source_ip} 不在資產清冊中，屬未知內部裝置，可能為未授權設備，需調查。",
                recommended_action="monitor",
            )

        # 規則 6: 同一來源短時間觸發多種 signature → 疑似掃描
        other_sig_count = freq.get("same_src_other_sig_24h", 0)
        if isinstance(other_sig_count, int) and other_sig_count > 5:
            return TriageVerdict(
                verdict="anomalous",
                confidence="medium",
                reasoning=f"同一來源 IP 過去 24h 觸發 {other_sig_count} 種不同 signature，疑似掃描行為。",
                recommended_action="monitor",
            )

        # 預設: 標記為需要人工覆核
        return TriageVerdict(
            verdict="anomalous",
            confidence="low",
            reasoning="未命中任何已知規則，需要人工判斷。",
            recommended_action="monitor",
        )

    async def _llm_triage(self, enriched: dict) -> TriageVerdict:
        """Phase 2: 呼叫 LLM 進行研判"""
        prompt = self._build_prompt(enriched)

        try:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    self.api_url,
                    headers=headers,
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": "你是一位資深資安分析師。請嚴格以 JSON 格式回應。"},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": self.temperature,
                        "max_tokens": self.max_tokens,
                    },
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                data = resp.json()

            # 解析 LLM 回應
            message = data["choices"][0]["message"]
            content = message.get("content") or ""

            # Fallback: 若 content 為空（chain-of-thought 模型可能只有 reasoning），
            # 嘗試從 reasoning 欄位中萃取 JSON block
            if not content:
                reasoning = message.get("reasoning") or ""
                m = re.search(r'\{[^{}]*"verdict"[^{}]*\}', reasoning, re.DOTALL)
                content = m.group(0) if m else ""

            # 清理前後空白與 markdown code fence
            content = content.strip()
            if content.startswith("```"):
                parts = content.split("\n", 1)
                content = parts[1] if len(parts) > 1 else ""
                content = content.rsplit("```", 1)[0].strip()

            if not content:
                raise ValueError("LLM returned empty content after parsing")

            parsed = json.loads(content)
            return TriageVerdict(**parsed)

        except Exception as e:
            logger.error(f"LLM triage failed: {e}", exc_info=True)
            # Fallback 到固定規則
            logger.info("Falling back to rule-based triage")
            return self._rule_based_triage(enriched)

    def _build_prompt(self, enriched: dict) -> str:
        """組裝 enriched context 到 prompt template"""
        summary = enriched.get("event_summary", {})
        asset = enriched.get("asset_context", {})
        freq = enriched.get("frequency_context", {})
        intel = enriched.get("threat_intel", {})

        src_asset = asset.get("source_asset", {})
        dst_asset = asset.get("destination_asset", {})

        # 使用 template 替換
        prompt = self.prompt_template
        replacements = {
            "{signature_id}": summary.get("signature_id", ""),
            "{signature_name}": summary.get("signature_name", ""),
            "{severity}": summary.get("severity", ""),
            "{action}": summary.get("action", ""),
            "{source_ip}": summary.get("source_ip", ""),
            "{source_user}": summary.get("source_user", ""),
            "{destination_ip}": summary.get("destination_ip", ""),
            "{destination_user}": summary.get("destination_user", ""),
            "{application_name}": summary.get("protocol", ""),
            "{network_transport}": "",  # 已包含在 protocol 中
            "{direction}": summary.get("direction", ""),
            "{source_zone}": summary.get("zone_flow", "").split(" → ")[0] if " → " in summary.get("zone_flow", "") else "",
            "{destination_zone}": summary.get("zone_flow", "").split(" → ")[-1] if " → " in summary.get("zone_flow", "") else "",
            "{rule_name}": summary.get("rule_name", ""),
            "{source_hostname}": src_asset.get("hostname", "unknown"),
            "{source_role}": src_asset.get("role", "unknown"),
            "{source_department}": src_asset.get("department", "unknown"),
            "{destination_hostname}": dst_asset.get("hostname", "unknown"),
            "{destination_role}": dst_asset.get("role", "unknown"),
            "{destination_department}": dst_asset.get("department", "unknown"),
            "{same_src_same_sig_24h}": str(freq.get("same_src_same_sig_24h", "N/A")),
            "{same_src_other_sig_24h}": str(freq.get("same_src_other_sig_24h", "N/A")),
            "{same_dst_same_sig_24h}": str(freq.get("same_dst_same_sig_24h", "N/A")),
            "{source_ip_reputation}": intel.get("source_ip_reputation", "N/A"),
            "{destination_ip_reputation}": intel.get("destination_ip_reputation", "N/A"),
        }

        for key, value in replacements.items():
            prompt = prompt.replace(key, value)

        return prompt

    @staticmethod
    def _is_internal(ip: str) -> bool:
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
