# 架構設計文件

## 1. 問題描述

Palo Alto Networks 防火牆產生大量 THREAT log，目前透過 Graylog pipeline rule 以 signature ID + action + IP 組合進行 RCVSS 分級（High / Medium / Low / None）。現有做法存在以下問題：

- Pipeline rule 超過 200 行且持續增長，維護成本高
- 判斷維度僅有靜態三元組，缺乏動態上下文
- 無回饋迴路，已標記的誤判無法定期覆核

## 2. 設計目標

- 將即時告警（High/Medium）推送至外部服務進行 enriched 研判
- 透過 LLM 產出結構化 verdict，降低人工判讀時間
- 建立 EDL 管理機制，支援自動阻擋與 TTL 過期
- 低風險事件（Low/None）改用 batch 趨勢分析

## 3. 系統架構

### 3.1 即時路線（High / Medium）

```
Graylog Event Definition (filter: RCVSS in [High, Medium])
    │
    ▼ HTTP Notification (webhook)
    │
FastAPI webhook_server.py
    │
    ├─ enrichment.py
    │   ├─ 資產清冊查詢 (assets.csv: IP → hostname, role, department)
    │   ├─ Graylog Search API (同 source_ip 近 24h 事件統計)
    │   └─ 威脅情資查詢 (AbuseIPDB / OTX, 僅外部 IP)
    │
    ├─ llm_client.py
    │   ├─ 組裝 enriched prompt (見 prompts/triage.md)
    │   └─ 呼叫內部 LLM，解析結構化回應
    │
    └─ 行動路由
        ├─ verdict=異常, confidence=high → 寄信 + 建議 EDL entry
        ├─ verdict=異常, confidence!=high → 寄信請人工判斷
        ├─ verdict=誤判 → 記錄到 known_fp.csv
        └─ verdict=正常 → 僅記錄 log
```

### 3.2 批次路線（Low / None）

```
Cron (每日 08:00)
    │
    ├─ 查 Graylog API：過去 24h RCVSS=None 的事件統計
    │   - 按 source_ip 分群
    │   - 按 signature 分群
    │   - 標記重複攻擊來源
    │
    ├─ LLM 趨勢摘要
    │
    └─ 寄送日報 / 週報
```

## 4. 資料流

### 4.1 Webhook Payload

Graylog HTTP Notification 預設會送出 event + backlog messages。
本服務解析 `backlog` 中的原始 log fields。

### 4.2 Enriched Context 結構

```json
{
  "event_summary": {
    "signature_id": "92322",
    "signature_name": "Microsoft Windows NTLMSSP Detection",
    "severity": "informational",
    "action": "alert",
    "source_ip": "10.0.5.48",
    "source_user": "CORP\\user01",
    "destination_ip": "10.0.1.10",
    "destination_user": "CORP\\svc_admin",
    "protocol": "msrpc-base / tcp",
    "direction": "client-to-server",
    "zone_flow": "Untrust-VPN → Trust",
    "rule_name": "VPN-to-Internal"
  },
  "asset_context": {
    "source_asset": {"hostname": "branch-pc01", "role": "user-endpoint", "department": "RD"},
    "destination_asset": {"hostname": "dc01", "role": "domain-controller", "department": "IT"}
  },
  "frequency_context": {
    "same_src_same_sig_24h": 47,
    "same_src_other_sig_24h": 0,
    "same_dst_same_sig_24h": 120
  },
  "threat_intel": {
    "source_ip_reputation": "N/A (internal)",
    "destination_ip_reputation": "N/A (internal)"
  }
}
```

### 4.3 LLM Verdict 結構

```json
{
  "verdict": "normal | false_positive | anomalous",
  "confidence": "high | medium | low",
  "reasoning": "NTLM authentication over MSRPC is expected behavior for domain-joined VPN clients accessing AD resources.",
  "recommended_action": "suppress | monitor | block",
  "edl_entry": null
}
```

## 5. EDL 管理

- EDL 檔案為純文字，每行一筆 IP/URL/domain
- 每筆 entry 附帶 metadata（加入時間、TTL、來源事件 ID）
- metadata 存於 `edl_metadata.json`，EDL 純文字檔由此產生
- Cron 定期檢查 TTL，過期自動移除
- PA 透過 HTTP 定期拉取 EDL 檔案

## 6. Phase 規劃

| Phase | 範圍 | 預估時間 |
|-------|------|----------|
| 1 | Webhook receiver + enrichment + 固定規則 + Email | 2 週 |
| 2 | 接入 LLM 替換固定規則 | 1-2 週 |
| 3 | EDL 自動管理 + 趨勢分析 + 週報 | 2-3 週 |
