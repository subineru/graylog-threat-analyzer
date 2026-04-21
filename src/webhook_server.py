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
    """Graylog HTTP Notification 的頂層結構"""
    model_config = ConfigDict(extra="ignore")

    event_definition_id: str | None = None
    event_definition_title: str | None = None
    event: dict | None = None
    backlog: list[dict] = []


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
    接收 Graylog webhook 推送的 THREAT 事件。

    處理流程：
    1. 驗證 webhook token
    2. 從 backlog 取出原始 log fields
    3. Context enrichment
    4. LLM 研判（Phase 2 啟用，Phase 1 用固定規則）
    5. 依據 verdict 採取行動
    """
    config = request.app.state.config

    # 1. Token 驗證
    expected_token = config.get("server", {}).get("webhook_token")
    if expected_token and x_webhook_token != expected_token:
        raise HTTPException(status_code=403, detail="Invalid webhook token")

    # 2. 解析 backlog
    if not payload.backlog:
        logger.warning("Received webhook with empty backlog, skipping.")
        return {"status": "skipped", "reason": "empty backlog"}

    results = []
    for message in payload.backlog:
        try:
            result = await process_single_event(request, message)
            results.append(result)
        except Exception as e:
            logger.error(f"Error processing event: {e}", exc_info=True)
            results.append({"status": "error", "error": str(e)})

    return {"status": "processed", "results": results}


async def process_single_event(request: Request, message: dict) -> dict:
    """處理單一 THREAT 事件"""
    enrichment_svc = request.app.state.enrichment
    llm_client = request.app.state.llm
    notifier = request.app.state.notifier
    edl_mgr = request.app.state.edl

    # 3. Context enrichment
    enriched = await enrichment_svc.enrich(message)

    # 4. 研判
    # Phase 1: 固定規則（先上線驗證流程）
    # Phase 2: 改用 LLM
    verdict = await llm_client.triage(enriched)

    # 5. 行動路由
    sig_name = message.get("alert_signature", "unknown")
    src_ip = message.get("source_ip", "unknown")
    dst_ip = message.get("destination_ip", "unknown")
    event_summary = f"[{verdict.verdict.upper()}] {sig_name} | {src_ip} → {dst_ip}"

    if verdict.verdict == "anomalous" and verdict.confidence == "high":
        await notifier.send_alert(
            subject=f"🔴 High Confidence Anomaly: {sig_name}",
            enriched_context=enriched,
            verdict=verdict,
        )
        if verdict.edl_entry:
            edl_mgr.suggest_entry(verdict.edl_entry, source_event=message)

    elif verdict.verdict == "anomalous":
        await notifier.send_alert(
            subject=f"🟡 Anomaly (needs review): {sig_name}",
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


@app.get("/health")
async def health_check():
    return {"status": "ok"}


if __name__ == "__main__":
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent))
    import uvicorn

    uvicorn.run("src.webhook_server:app", host="0.0.0.0", port=8000, reload=True)
