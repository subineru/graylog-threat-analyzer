"""
Graylog Threat Analyzer - Webhook Server
接收 Graylog HTTP Notification，進行 enrichment 與 LLM 研判。
"""

import logging
from contextlib import asynccontextmanager

import yaml
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from .edl_manager import EDLManager
from .enrichment import EnrichmentService
from .notifier import EmailNotifier
from .triage_engine import TriageEngine

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
    event_title: str | None = None
    event_id: str | None = None
    event_timestamp: str | None = None
    event_priority: int | None = None
    fields: dict = {}
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

    signature_name = f.get("signature_name", "")
    threat_id = f.get("threat_id", "")
    alert_signature = signature_name or threat_id

    return {
        "event_uid":            payload.event_id or "",
        "event_timestamp":      payload.event_timestamp or "",
        "alert_signature":      alert_signature,
        "threat_id":            threat_id,
        "signature_name":       signature_name or (f"ThreatID {threat_id}" if threat_id else "unknown"),
        "threat_content_type":  f.get("threat_content_type", ""),
        "file_name":            f.get("file_name", ""),
        "vendor_event_action":  f.get("action", ""),
        "vendor_alert_severity": f.get("severity", ""),
        "RCVSS":                f.get("rcvss", ""),
        "source_ip":            f.get("source_address", ""),
        "source_user_name":     f.get("source_user", ""),
        "source_location":      f.get("source_location", ""),
        "destination_ip":       f.get("destination_address", ""),
        "destination_user_name": f.get("destination_user", ""),
        "destination_port":     str(f.get("destination_port", "")),
        "application_name":     f.get("application", ""),
        "network_transport":    f.get("transport", ""),
        "pan_alert_direction":  f.get("direction", ""),
        "source_zone":          f.get("source_zone", ""),
        "destination_zone":     f.get("destination_zone", ""),
        "rule_name":            f.get("rule_name", ""),
        "firewall":             f.get("firewall", ""),
    }


# --- Application ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    """啟動時載入設定與初始化各模組"""
    config = load_config()
    app.state.config = config
    app.state.enrichment = EnrichmentService(config)
    app.state.triage = TriageEngine(config)
    app.state.notifier = EmailNotifier(config)
    app.state.edl = EDLManager(config)

    logger.info("Graylog Threat Analyzer started.")
    yield
    logger.info("Graylog Threat Analyzer stopped.")


app = FastAPI(
    title="Graylog Threat Analyzer",
    version="0.2.0",
    lifespan=lifespan,
)


@app.post("/webhook/graylog")
@app.post("/webhook")
async def receive_graylog_webhook(
    request: Request,
    payload: GraylogEvent,
    background_tasks: BackgroundTasks,
    x_webhook_token: str | None = Header(default=None),
):
    """
    接收 Graylog Custom HTTP Notification。
    驗證通過後立即回傳 202，研判流程於背景執行。
    """
    config = request.app.state.config

    # Token 驗證
    expected_token = config.get("server", {}).get("webhook_token")
    if expected_token and x_webhook_token != expected_token:
        raise HTTPException(status_code=403, detail="Invalid webhook token")

    if not payload.fields:
        logger.warning("Received webhook with empty fields, skipping.")
        return {"status": "skipped", "reason": "empty fields"}

    # 在 request context 取得 base_url，BackgroundTask 中無法取得 Request
    base_url = str(request.base_url).rstrip("/")
    background_tasks.add_task(
        _process_event_bg, request.app.state, payload, base_url
    )
    return {"status": "queued"}


async def _process_event_bg(state, payload: GraylogEvent, base_url: str) -> None:
    """BackgroundTask wrapper：錯誤記錄 log 但不影響已回傳的 HTTP response。"""
    try:
        await process_single_event(state, payload, base_url)
    except Exception as e:
        logger.error(f"Background event processing failed: {e}", exc_info=True)


async def process_single_event(state, payload: GraylogEvent, base_url: str = "") -> dict:
    """處理單一 THREAT 事件（Rate Limit → Gate 1 → Gate 3 → 行動路由）"""
    enrichment_svc = state.enrichment
    triage_engine = state.triage
    notifier = state.notifier
    edl_mgr = state.edl

    message = _normalize_event_fields(payload)
    enriched = await enrichment_svc.enrich(message)
    verdict = await triage_engine.triage(enriched)

    sig = message.get("alert_signature") or message.get("signature_name") or "unknown"
    src_ip = message.get("source_ip", "unknown")
    dst_ip = message.get("destination_ip", "unknown")
    event_summary = f"[{verdict.verdict.upper()}] ThreatID={sig} | {src_ip} → {dst_ip}"

    if verdict.verdict == "duplicate":
        logger.debug(f"Suppressed duplicate: {event_summary}")

    elif verdict.verdict == "anomalous" and verdict.confidence == "high":
        edl_approve_url = None
        if verdict.edl_entry:
            token = edl_mgr.suggest_entry(verdict.edl_entry, source_event=message)
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
        logger.info(f"False positive suppressed: {event_summary}")

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
