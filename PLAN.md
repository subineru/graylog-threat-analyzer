# Sidebar Navigation + Email Redesign + Simplify Fixes

## Status

- ✅ A1: `src/report_generator.py` — lxml import 移至頂層
- ✅ A2: `src/webhook_server.py` — `/report/pptx` 改 run_in_executor
- ✅ A3: `src/whitelist_manager.py` — approve_rule() 改 in-memory append + write_back
- ✅ C: `src/notifier.py` — email HTML 全重寫（680px 專業風格）
- ⏳ A4: `static/dashboard.html` — setInterval 加 document.hidden guard（Stage 2）
- ⏳ B: `static/dashboard.html` — Sidebar 導航架構（Stage 2）

---

## Part B：Sidebar Navigation 架構（待完成）

### B1 整體佈局

`static/dashboard.html` 從「單欄捲動」改為「左 sidebar + 右內容區」。

```
┌─────────────────────────────────────────────┐
│  ████████  Graylog Threat Analyzer   header │
├──────────┬──────────────────────────────────┤
│ sidebar  │  <section id="s-dashboard">      │
│ (220px)  │  <section id="s-events">         │
│  nav     │  <section id="s-edl">            │
│  links   │  <section id="s-whitelist">      │
│          │  <section id="s-audit">          │
│          │  <section id="s-system">         │
└──────────┴──────────────────────────────────┘
```

**Layout CSS**:
```css
body { display: flex; flex-direction: column; height: 100vh; overflow: hidden; }
.app { display: flex; flex: 1; overflow: hidden; }
.sidebar { width: 220px; background: var(--navy); display: flex; flex-direction: column;
           overflow-y: auto; flex-shrink: 0; }
.content { flex: 1; overflow-y: auto; padding: 24px 28px 48px; }
header { height: 52px; background: var(--navy); color: #fff; ... flex-shrink: 0; }
```

### B2 Sidebar 導航項目

| 圖示 | 標籤 | section id | 內容 |
|------|------|------------|------|
| 📊 | Dashboard | s-dashboard | KPI、分布圖、趨勢（現有內容）|
| 🔍 | Events | s-events | Blocked events + Pending events（現有兩個表格）|
| 🛡 | EDL | s-edl | Active block list + Pending approval（現有兩個表格）|
| 📋 | Whitelist | s-whitelist | Whitelist rules 管理（現有一個表格）|
| 📁 | Audit Log | s-audit | 未來可加；目前顯示「功能開發中」placeholder |
| ⚙ | System | s-system | Health、設定概覽、API Docs 連結 |

### B3 導航 JavaScript（hash routing）

```js
function showSection(id) {
  document.querySelectorAll('.content > section').forEach(s => s.hidden = true);
  document.querySelectorAll('.nav-link').forEach(a => a.classList.remove('active'));
  const section = document.getElementById('s-' + id);
  if (section) section.hidden = false;
  document.querySelector(`.nav-link[data-sec="${id}"]`)?.classList.add('active');
  location.hash = id;
}

window.addEventListener('hashchange', () => {
  const id = location.hash.slice(1) || 'dashboard';
  showSection(id);
});
```

### B4 Sidebar CSS

```css
.sidebar { ... }
.nav-link {
  display: flex; align-items: center; gap: 10px;
  padding: 11px 20px; color: rgba(255,255,255,.75);
  font-size: 13px; font-weight: 500; cursor: pointer;
  border-left: 3px solid transparent; transition: background .15s, color .15s;
  text-decoration: none;
}
.nav-link:hover { background: rgba(255,255,255,.08); color: #fff; }
.nav-link.active { background: rgba(255,255,255,.12); color: #fff;
                   border-left-color: var(--light-bg); }
.nav-section-label { font-size: 10px; text-transform: uppercase; letter-spacing: 1px;
                     color: rgba(255,255,255,.4); padding: 18px 20px 6px; }
```

### B5 System Section 內容

```html
<section id="s-system" hidden>
  <h2>System</h2>
  <div class="panels">
    <div class="panel">
      <div class="panel-head">Service Health</div>
      <div class="panel-body" id="sys-health-body">Loading…</div>
    </div>
    <div class="panel">
      <div class="panel-head">Quick Links</div>
      <div class="panel-body">
        <a href="/docs" target="_blank">API Documentation (Swagger)</a><br>
        <a href="/health">Health Endpoint (JSON)</a>
      </div>
    </div>
  </div>
</section>
```

---

## 實作順序（剩餘）

1. `static/dashboard.html` — A4 + B sidebar 全重寫
2. git commit + push
