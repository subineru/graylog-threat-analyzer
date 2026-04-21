# Graylog Threat Analyzer

Palo Alto Networks THREAT log 自動化分類與研判系統。

## 概述

接收 Graylog webhook 推送的 PA THREAT 事件，透過 context enrichment 與內部 LLM 進行智慧研判，產出結構化的 verdict（異常 / 誤判 / 正常），並依據風險等級採取對應行動（通知、EDL 阻擋建議）。

## 架構

```
PA Syslog → Graylog Pipeline (RCVSS 粗分類)
                    │
                    ▼ webhook (RCVSS High/Med)
         ┌─────────────────────┐
         │  FastAPI Service    │
         │  1. Enrichment      │  ← 資產清冊、Graylog API、威脅情資
         │  2. LLM 研判        │  ← 內部 Local LLM
         │  3. 行動路由        │  → Email / EDL / known_fp.csv
         └─────────────────────┘

         Cron (每日) → RCVSS None/Low 趨勢分析 → 週報
```

## 功能模組

| 模組 | 說明 |
|------|------|
| `webhook_server.py` | FastAPI 接收 Graylog webhook |
| `enrichment.py` | Context enrichment（資產、頻率、威脅情資）|
| `llm_client.py` | 內部 LLM API 封裝 |
| `notifier.py` | Email 通知 |
| `edl_manager.py` | EDL 檔案管理（含 TTL 自動過期）|

## 快速開始

```bash
# 安裝依賴
pip install -r requirements.txt

# 複製設定檔
cp config/config.example.yaml config/config.yaml
# 編輯 config.yaml 填入實際設定

# 啟動服務
uvicorn src.webhook_server:app --host 0.0.0.0 --port 8000
```

## 設定

詳見 `config/config.example.yaml`，需設定：
- Graylog API 連線資訊（用於 enrichment 查詢）
- 內部 LLM endpoint
- SMTP 寄信設定
- EDL 輸出路徑

## 開發階段

- **Phase 1**：Webhook receiver + enrichment + 固定規則 + Email 通知
- **Phase 2**：接入 LLM 研判，替換固定規則
- **Phase 3**：EDL 自動管理 + 趨勢分析週報
