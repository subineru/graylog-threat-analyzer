"""
Graylog API 可用性測試腳本

執行方式：
    python scripts/test_graylog_histogram.py

測試項目：
  Test 1  /search/universal/relative  — 現有 API（基準確認）
  Test 2  /search/universal/histogram — 舊 histogram API（Graylog 6.x 預期 404）
  Test 3  POST /views/search/sync     — Views API，auto interval
  Test 4  POST /views/search/sync     — Views API，固定 1 天 interval
  計算示範：若任一 Views 測試成功，計算 μ、σ、z-score
"""

import asyncio
import json
import math
import sys
from pathlib import Path

import httpx
import yaml

# ── 讀取 config ───────────────────────────────────────────────────────────────

CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.yaml"

if not CONFIG_PATH.exists():
    print(f"[ERROR] 找不到設定檔：{CONFIG_PATH}")
    print("        請先複製 config/config.example.yaml → config/config.yaml 並填入連線資訊")
    sys.exit(1)

with open(CONFIG_PATH, encoding="utf-8") as f:
    config = yaml.safe_load(f)

graylog_cfg = config.get("graylog", {})
API_URL   = graylog_cfg.get("api_url", "").rstrip("/")
API_TOKEN = graylog_cfg.get("api_token", "")

if not API_URL or not API_TOKEN or "YOUR_GRAYLOG" in API_URL:
    print("[ERROR] config.yaml 中的 graylog.api_url / graylog.api_token 尚未填入實際值")
    sys.exit(1)

print(f"Graylog API: {API_URL}")
print("-" * 60)

# ── 共用參數 ──────────────────────────────────────────────────────────────────

TEST_QUERY    = "*"
RANGE_30D_SEC = 30 * 24 * 3600
RANGE_24H_SEC = 24 * 3600

GET_HEADERS  = {"Accept": "application/json"}
POST_HEADERS = {"Accept": "application/json", "Content-Type": "application/json", "X-Requested-By": "cli"}
AUTH         = (API_TOKEN, "token")


# ── Test 1：relative API（基準）──────────────────────────────────────────────

async def test_relative() -> bool:
    print("\n[Test 1] GET /search/universal/relative（現有 API，確認連線正常）")
    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(
                f"{API_URL}/search/universal/relative",
                params={"query": TEST_QUERY, "range": RANGE_24H_SEC,
                        "limit": 1, "fields": "timestamp"},
                headers=GET_HEADERS,
                auth=AUTH,
                timeout=15,
            )
        resp.raise_for_status()
        data = json.JSONDecoder().raw_decode(resp.text.strip())[0]
        print(f"  → HTTP 200 OK  |  過去 24h 事件總數: {data.get('total_results', 'N/A')}")
        return True
    except Exception as e:
        print(f"  → FAILED: {e}")
        return False


# ── Test 2：舊 histogram API（預期 404）──────────────────────────────────────

async def test_histogram() -> None:
    print("\n[Test 2] GET /search/universal/histogram（舊 API，Graylog 6.x 預期 404）")
    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(
                f"{API_URL}/search/universal/histogram",
                params={"query": TEST_QUERY, "range": RANGE_30D_SEC, "interval": "day"},
                headers=GET_HEADERS,
                auth=AUTH,
                timeout=15,
            )
        if resp.status_code == 404:
            print("  → HTTP 404（確認：此端點已移除）")
        else:
            print(f"  → HTTP {resp.status_code}（預期外）: {resp.text[:120]}")
    except Exception as e:
        print(f"  → FAILED: {e}")


# ── Views API 共用：建立 query body ──────────────────────────────────────────

def _views_body(interval_config: dict) -> dict:
    return {
        "queries": [{
            "id": "q1",
            "query": {"type": "elasticsearch", "query_string": TEST_QUERY},
            "timerange": {"type": "relative", "range": RANGE_30D_SEC},
            "search_types": [{
                "id": "st1",
                "type": "pivot",
                "row_groups": [{
                    "type": "time",
                    "field": "timestamp",
                    "interval": interval_config,
                }],
                "column_groups": [],
                "series": [{"type": "count", "id": "count()"}],
                "rollup": True,
                "filter": None,
                "streams": [],
            }],
        }]
    }


def _extract_daily_counts(data: dict) -> list[int] | None:
    """從 Views API response 提取每日計數列表。"""
    try:
        rows = (
            data["results"]["q1"]
            ["search_types"]["st1"]
            ["rows"]
        )
    except (KeyError, TypeError):
        return None

    counts = []
    for row in rows:
        if row.get("source") == "non-leaf":
            continue
        for val in row.get("values", []):
            if val.get("key") == ["count()"]:
                counts.append(int(val.get("value") or 0))
                break

    return counts if counts else None


async def _call_views(label: str, interval_config: dict) -> list[int] | None:
    body = _views_body(interval_config)
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.post(
            f"{API_URL}/views/search/sync",
            content=json.dumps(body),
            headers=POST_HEADERS,
            auth=AUTH,
            timeout=30,
        )

    print(f"  → HTTP {resp.status_code}")

    if resp.status_code in (404, 405):
        print(f"  → {resp.status_code}：端點不存在或方法不允許")
        return None

    if not resp.text.strip():
        print("  → 空回應")
        return None

    try:
        data = json.JSONDecoder().raw_decode(resp.text.strip())[0]
    except json.JSONDecodeError:
        print(f"  → JSON 解析失敗，原始回應（前 300 字）：\n  {resp.text[:300]}")
        return None

    if resp.status_code >= 400:
        # 顯示錯誤細節
        err = data.get("message") or data.get("error") or str(data)[:200]
        print(f"  → 錯誤：{err}")
        return None

    # 顯示 response 頂層結構（debug 用）
    top_keys = list(data.keys())
    print(f"  → Response 頂層 keys: {top_keys}")

    # 嘗試提取每日計數
    daily = _extract_daily_counts(data)

    if daily is None:
        # 顯示深層結構供 debug
        try:
            st = data["results"]["q1"]["search_types"]["st1"]
            print(f"  → search_type keys: {list(st.keys())}")
            rows = st.get("rows", [])
            print(f"  → rows 數量: {len(rows)}")
            if rows:
                print(f"  → 第一筆 row 範例: {json.dumps(rows[0], ensure_ascii=False)[:200]}")
        except (KeyError, TypeError):
            print(f"  → 無法解析 search_types 結構，完整 response（前 500 字）：")
            print(f"  {resp.text[:500]}")
        return None

    print(f"  → 成功取得 {len(daily)} 天的每日計數")
    print(f"  → 最近 10 天：{daily[-10:]}")
    return daily


# ── Test 3：Views API，auto interval ─────────────────────────────────────────

async def test_views_auto() -> list[int] | None:
    print("\n[Test 3] POST /views/search/sync（interval: auto）")
    return await _call_views(
        "auto",
        {"type": "auto", "scaling": 1.0},
    )


# ── Test 4：Views API，固定 1 天 interval ────────────────────────────────────

async def test_views_day() -> list[int] | None:
    print("\n[Test 4] POST /views/search/sync（interval: timeunit 1 day）")
    return await _call_views(
        "1day",
        {"type": "timeunit", "timeunit": "1d"},
    )


# ── 統計計算示範 ──────────────────────────────────────────────────────────────

def compute_stats(daily_counts: list[int], source: str) -> None:
    print(f"\n[統計示範] 資料來源：{source}")
    if len(daily_counts) < 3:
        print("  → 資料點不足（需至少 3 天）")
        return

    n   = len(daily_counts)
    mu  = sum(daily_counts) / n
    var = sum((x - mu) ** 2 for x in daily_counts) / n
    sig = math.sqrt(var)
    today = daily_counts[-1]
    z   = (today - mu) / (sig + 1e-9)

    print(f"  資料天數: {n} 天")
    print(f"  日均值 μ: {mu:.1f}  |  標準差 σ: {sig:.1f}")
    print(f"  最近一天: {today} 次  |  z-score: {z:.2f}")

    level = ("高度異常（>3σ）" if z >= 3 else
             "明顯異常（2~3σ）" if z >= 2 else
             "輕微偏高（1~2σ）" if z >= 1 else "正常範圍")
    print(f"  評估: {level}")
    print(f"\n  LLM 接收範例：「今日觸發 {today} 次（日均 {mu:.1f}、σ={sig:.1f}、z={z:.1f}）」")


# ── 主流程 ────────────────────────────────────────────────────────────────────

async def main() -> None:
    if not await test_relative():
        print("\n[ABORT] 基本連線失敗，請確認 API URL / Token")
        return

    await test_histogram()

    daily_auto = await test_views_auto()
    daily_day  = await test_views_day()

    print("\n" + "=" * 60)
    print("[結論]")

    if daily_auto is not None:
        print("  Views API（auto interval）可用 ✓")
        compute_stats(daily_auto, "Views auto")
    elif daily_day is not None:
        print("  Views API（timeunit 1day）可用 ✓")
        compute_stats(daily_day, "Views timeunit:day")
    else:
        print("  Views API 不可用（Test 3 / 4 均失敗）")
        print("  → 將改用方案 C：多時間窗口 ratio（+1 個 relative 查詢）")

    print("=" * 60)


asyncio.run(main())
