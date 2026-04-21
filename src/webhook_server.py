"""
Graylog Threat Analyzer - Webhook Server
接收 Graylog HTTP Notification，進行 enrichment 與 LLM 研判。
"""

import logging
from contextlib import asynccontextmanager

import yaml
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from .enrichment import EnrichmentService
from .llm_client import LLMClient
from .notifier import EmailNotifier
from .edl_manager import EDLManager

logger = logging.getLogger(__name__)


def load_config(path: str = "config/config.yaml") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# --- Pydantic Models ---

class GraylogEvent(BaseModel):
    """
    Graylog Custom HTTP Notification 的頂層結構。

    對應 JMTE Body Template 格式：
      - fields：事件欄位（source_address、action、rcvss 等）
      - backlog：觸發本事件的原始 messages（選用，內容視 template 而定）
    """
    model_config = ConfigDict(extra="ignore")

    event_definition_id: str | None = None
    event_title: str | None = None          # 對應 template 的 event_title
    event_id: str | None = None
    event_timestamp: str | None = None
    event_priority: int | None = None
    fields: dict = {}                        # 所有事件欄位都在這裡
    backlog: list[dict] = []


def _normalize_event_fields(payload: GraylogEvent) -> dict:
    """
    將 Graylog Custom HTTP Notification 的 fields 轉成程式內部通用格式。

    欄位對照（JMTE template key → 內部欄位名稱）：
      source_address       → source_ip
      destination_address  → destination_ip
      source_user          → source_user_name
      destination_user     → destination_user_name
      action               → vendor_event_action
      threat_id            → threat_id  （ThreatID，純數字，如 "92322"）
      signature_name       → alert_signature + signature_name
                             （建議加入 JMTE：event.fields.alert_signature）
      rcvss                → RCVSS

    建議在 Graylog Event Definition 的「Fields」區塊新增以下 field extraction，
    然後在 JMTE Body Template 的 "fields" 物件中加入對應鍵值（詳見 config.example.yaml）：
      severity / signature_name / source_zone / destination_zone /
      rule_name / transport / direction
    """
    f = payload.fields

    # alert_signature：優先使用完整格式 "Name(ID)"（signature_name），
    # 若尚未加入 JMTE 則 fallback 到純數字 threat_id
    signature_name = f.get("signature_name", "")      # e.g. "NTLMSSP Detection(92322)"
    threat_id = f.get("threat_id", "")                # e.g. "92322"
    alert_signature = signature_name or threat_id     # 優先完整格式，供 triage 和 email 顯示

    return {
        # 識別
        "event_uid":            payload.event_id or "",
        "event_timestamp":      payload.event_timestamp or "",
        # 威脅
        "alert_signature":      alert_signature,
        "threat_id":            threat_id,
        "signature_name":       signature_name or (f"ThreatID {threat_id}" if threat_id else "unknown"),
        "threat_content_type":  f.get("threat_content_type", ""),
        "file_name":            f.get("file_name", ""),
        # 行動 / 嚴重性
        "vendor_event_action":  f.get("action", ""),
        "vendor_alert_severity": f.get("severity", ""),   # 加入 JMTE 後才有值
        "RCVSS":                f.get("rcvss", ""),
        # 來源
        "source_ip":            f.get("source_address", ""),
        "source_user_name":     f.get("source_user", ""),
        "source_location":      f.get("source_location", ""),
        # 目標
        "destination_ip":       f.get("destination_address", ""),
        "destination_user_name": f.get("destination_user", ""),
        "destination_port":     str(f.get("destination_port", "")),
        # 網路環境（加入 JMTE 後才有值）
        "application_name":     f.get("application", ""),
        "network_transport":    f.get("transport", ""),
        "pan_alert_direction":  f.get("direction", ""),
        "source_zone":          f.get("source_zone", ""),
        "destination_zone":     f.get("destination_zone", ""),
        "rule_name":            f.get("rule_name", ""),
        # 防火牆
        "firewall":             f.get("firewall", ""),
    }


# --- Application ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    """啟動時載入設定與初始化各模組"""
    config = load_config()
    app.state.config = config
    app.state.enrichment = EnrichmentService(config)
    app.state.llm = LLMClient(config)
    app.state.notifier = EmailNotifier(config)
    app.state.edl = EDLManager(config)

    logger.info("Graylog Threat Analyzer started.")
    yield
    logger.info("Graylog Threat Analyzer stopped.")


app = FastAPI(
    title="Graylog Threat Analyzer",
    version="0.1.0",
    lifespan=lifespan,
)


@app.post("/webhook/graylog")
async def receive_graylog_webhook(
    request: Request,
    payload: GraylogEvent,
    x_webhook_token: str | None = Header(default=None),
):
    """
    接收 Graylog Custom HTTP Notification。

    處理流程：
    1. 驗證 webhook token
    2. 從 payload.fields 取出正規化後的事件欄位
    3. Context enrichment（資產查詢、頻率分析、威脅情資）
    4. LLM 研判（Phase 1: 固定規則 / Phase 2: LLM）
    5. 依據 verdict 採取行動（email / EDL pending）
    """
    config = request.app.state.config

    # 1. Token 驗證
    expected_token = config.get("server", {}).get("webhook_token")
    if expected_token and x_webhook_token != expected_token:
        raise HTTPException(status_code=403, detail="Invalid webhook token")

    # 2. 確認 fields 不為空（Test Notification 時 fields 全為空值屬正常）
    if not payload.fields:
        logger.warning("Received webhook with empty fields, skipping.")
        return {"status": "skipped", "reason": "empty fields"}

    try:
        result = await process_single_event(request, payload)
    except Exception as e:
        logger.error(f"Error processing event: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}

    return {"status": "processed", "result": result}


async def process_single_event(request: Request, payload: GraylogEvent) -> dict:
    """處理單一 THREAT 事件"""
    enrichment_svc = request.app.state.enrichment
    llm_client = request.app.state.llm
    notifier = request.app.state.notifier
    edl_mgr = request.app.state.edl

    # 將 Graylog payload 正規化為內部格式
    message = _normalize_event_fields(payload)

    # 3. Context enrichment
    enriched = await enrichment_svc.enrich(message)

    # 4. 研判（Phase 1: 固定規則 / Phase 2: LLM）
    verdict = await llm_client.triage(enriched)

    # 5. 行動路由
    sig = message.get("alert_signature") or message.get("signature_name") or "unknown"
    src_ip = message.get("source_ip", "unknown")
    dst_ip = message.get("destination_ip", "unknown")
    event_summary = f"[{verdict.verdict.upper()}] ThreatID={sig} | {src_ip} → {dst_ip}"

    if verdict.verdict == "anomalous" and verdict.confidence == "high":
        edl_approve_url = None
        if verdict.edl_entry:
            token = edl_mgr.suggest_entry(verdict.edl_entry, source_event=message)
            base_url = str(request.base_url).rstrip("/")
            edl_approve_url = f"{base_url}/edl/approve/{token}"

        await notifier.send_alert(
            subject=f"🔴 High Confidence Anomaly: ThreatID={sig}",
            enriched_context=enriched,
            verdict=verdict,
            edl_approve_url=edl_approve_url,
        )

    elif verdict.verdict == "anomalous":
        await notifier.send_alert(
            subject=f"🟡 Anomaly (needs review): ThreatID={sig}",
            enriched_context=enriched,
            verdict=verdict,
        )

    elif verdict.verdict == "false_positive":
        logger.info(f"False positive recorded: {event_summary}")
        # TODO: 自動寫入 known_fp.csv

    else:
        logger.info(f"Normal event: {event_summary}")

    return {
        "status": "processed",
        "verdict": verdict.model_dump(),
        "summary": event_summary,
    }


@app.get("/edl/approve/{token}")
async def edl_approve(token: str, request: Request):
    """點擊 email 中的確認連結後呼叫此 endpoint，將 pending EDL 條目正式寫入。"""
    edl_mgr = request.app.state.edl
    success, message = edl_mgr.approve_entry(token)
    if success:
        return {"status": "approved", "message": message}
    raise HTTPException(status_code=400, detail=message)


@app.get("/edl/reject/{token}")
async def edl_reject(token: str, request: Request):
    """拒絕 pending EDL 條目（不寫入 EDL）。"""
    edl_mgr = request.app.state.edl
    success, message = edl_mgr.reject_entry(token)
    if success:
        return {"status": "rejected", "message": message}
    raise HTTPException(status_code=400, detail=message)


@app.get("/edl/pending")
async def edl_list_pending(request: Request):
    """列出所有待審的 EDL 條目（管理用）。"""
    edl_mgr = request.app.state.edl
    return {"pending": edl_mgr.list_pending()}


@app.get("/health")
async def health_check():
    return {"status": "ok"}


if __name__ == "__main__":
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent))
    import uvicorn

    uvicorn.run("src.webhook_server:app", host="0.0.0.0", port=8000, reload=True)
