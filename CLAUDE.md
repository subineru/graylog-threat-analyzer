# CLAUDE.md

## 專案概述
Graylog Threat Analyzer — 接收 Palo Alto Networks 防火牆 THREAT log（透過 Graylog webhook），進行 context enrichment 與 LLM 研判，自動分類事件為異常/誤判/正常，並採取對應行動（Email 通知、EDL 阻擋建議）。

## 技術棧
- Python 3.11+
- FastAPI + Uvicorn
- httpx（async HTTP client，用於 Graylog API 與 LLM API）
- aiosmtplib（async email）
- Pydantic v2（資料驗證）
- PyYAML（設定檔）

## 專案結構
```
src/
  webhook_server.py   # FastAPI 主入口，接收 webhook
  enrichment.py       # Context enrichment（資產、頻率、威脅情資）
  llm_client.py       # LLM 封裝（Phase 1: 固定規則 / Phase 2: LLM）
  notifier.py         # Email 通知
  edl_manager.py      # EDL 檔案管理（含 TTL）
config/
  config.example.yaml # 設定範本
  assets.csv          # IP → 主機角色清冊
  known_fp.csv        # 已知誤判清單
prompts/
  triage.md           # LLM prompt template
```

## 關鍵設計決策
1. Phase 1 不接 LLM，用固定規則跑通整個 pipeline，驗證可靠性
2. LLM 不直接看 raw log，而是看 enriched context（資產角色、頻率、情資）
3. EDL entry 有 TTL，過期自動移除，避免只進不出
4. Email 以 HTML 格式呈現結構化研判結果

## 執行方式
```bash
pip install -r requirements.txt
cp config/config.example.yaml config/config.yaml
# 編輯 config.yaml
uvicorn src.webhook_server:app --host 0.0.0.0 --port 8000
```

## 測試
```bash
pytest tests/ -v
```

## 環境備註
- Graylog 位於內部網段（IP 見 config.yaml）
- PA 防火牆：Palo Alto（多台，透過 Panorama 管理）
- 內部網段：RFC1918 地址空間
- LLM 為公司內部自建，API 相容 OpenAI chat completions 格式
- SMTP 為公司內部郵件伺服器

## 機敏資料處理
- `config/assets.csv` 和 `config/known_fp.csv` 為範例資料，需替換為實際環境資訊
- 實際 IP、主機名、人員帳號等機敏資料不應 commit 到 repo
- `config/config.yaml`（含實際連線資訊）已在 `.gitignore` 中排除
