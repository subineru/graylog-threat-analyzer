# Sidebar Navigation + Email Redesign + Simplify Fixes

## Status：全部完成 ✅

| 項目 | 檔案 | 說明 |
|------|------|------|
| ✅ A1 | `src/report_generator.py` | lxml import 移至頂層（line 11） |
| ✅ A2 | `src/webhook_server.py` | `/report/pptx` 改 run_in_executor（line 520） |
| ✅ A3 | `src/whitelist_manager.py` | `approve_rule()` 改 in-memory append + write_back |
| ✅ A4 | `static/dashboard.html` | setInterval 加 `document.hidden` guard |
| ✅ B  | `static/dashboard.html` | Sidebar 導航架構（6 sections + hash routing） |
| ✅ C  | `src/notifier.py` | Email HTML 全重寫（680px 專業風格） |

無待辦事項。
