"""
Graylog Histogram API 可用性測試腳本

執行方式：
    python scripts/test_graylog_histogram.py

會自動讀取 config/config.yaml，測試三個 API：
  1. /search/universal/relative  — 現有頻率查詢（基準）
  2. /search/universal/histogram — 每日計數（z-score 方案所需）
  3. 計算示範：從 histogram 結果算出 μ 和 σ
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
    print("        請先複製 config/config.example.yaml → config/config.yaml 並填入 Graylog 連線資訊")
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

# 測試用查詢：所有事件（可換成實際欄位，例如 'source_ip:"10.1.2.3"'）
TEST_QUERY     = "*"
RANGE_30D_SEC  = 30 * 24 * 3600   # 30 天（秒）
RANGE_24H_SEC  = 24 * 3600        # 24 小時（秒）

COMMON_HEADERS = {"Accept": "application/json"}
AUTH           = (API_TOKEN, "token")


# ── 測試 1：現有 relative API（基準確認）────────────────────────────────────

async def test_relative() -> bool:
    print("\n[Test 1] /search/universal/relative（現有 API，確認連線正常）")
    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(
                f"{API_URL}/search/universal/relative",
                params={"query": TEST_QUERY, "range": RANGE_24H_SEC, "limit": 1, "fields": "timestamp"},
                headers=COMMON_HEADERS,
                auth=AUTH,
                timeout=15,
            )
        resp.raise_for_status()
        data = json.JSONDecoder().raw_decode(resp.text.strip())[0]
        total = data.get("total_results", "N/A")
        print(f"  → HTTP {resp.status_code} OK  |  過去 24h 事件總數: {total}")
        return True
    except Exception as e:
        print(f"  → FAILED: {e}")
        return False


# ── 測試 2：histogram API（每日計數）────────────────────────────────────────

async def test_histogram() -> list[int] | None:
    print("\n[Test 2] /search/universal/histogram（每日計數，z-score 方案所需）")
    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(
                f"{API_URL}/search/universal/histogram",
                params={
                    "query":    TEST_QUERY,
                    "range":    RANGE_30D_SEC,
                    "interval": "day",
                },
                headers=COMMON_HEADERS,
                auth=AUTH,
                timeout=15,
            )

        print(f"  → HTTP {resp.status_code}")

        if resp.status_code == 404:
            print("  → 404：此 Graylog 版本不支援 histogram endpoint，請確認版本（需 Graylog 3.x+）")
            return None

        resp.raise_for_status()
        data = json.JSONDecoder().raw_decode(resp.text.strip())[0]

        # histogram 回傳格式：{"results": {"<unix_ts>": count, ...}, "time": ..., "interval": ...}
        results = data.get("results", {})
        if not results:
            print("  → 回應成功但 results 為空（查詢範圍內無資料）")
            return []

        # 依時間排序，取出每日計數
        daily_counts = [v for _, v in sorted(results.items())]

        print(f"  → 取得 {len(daily_counts)} 天的每日計數")
        print(f"  → 最近 10 天：{daily_counts[-10:]}")
        return daily_counts

    except httpx.HTTPStatusError as e:
        print(f"  → HTTP error {e.response.status_code}: {e.response.text[:200]}")
        return None
    except Exception as e:
        print(f"  → FAILED: {e}")
        return None


# ── 測試 3：用 histogram 結果算 μ 和 σ ──────────────────────────────────────

def compute_stats(daily_counts: list[int]) -> None:
    print("\n[Test 3] 統計計算示範（μ 和 σ）")
    if len(daily_counts) < 3:
        print("  → 資料點不足（需至少 3 天），無法計算有意義的統計值")
        return

    n   = len(daily_counts)
    mu  = sum(daily_counts) / n
    var = sum((x - mu) ** 2 for x in daily_counts) / n
    sig = math.sqrt(var)

    today = daily_counts[-1]  # 最近一天作為「今日」示範
    z     = (today - mu) / (sig + 1e-9)  # 避免 σ=0 時除以零

    print(f"  → 資料天數: {n} 天")
    print(f"  → 日均值 μ: {mu:.1f} 次/天")
    print(f"  → 標準差 σ: {sig:.1f}")
    print(f"  → 最近一天: {today} 次")
    print(f"  → z-score:  {z:.2f}")

    if   z >= 3:  level = "高度異常（> 3σ）"
    elif z >= 2:  level = "明顯異常（2~3σ）"
    elif z >= 1:  level = "輕微偏高（1~2σ）"
    else:         level = "正常範圍"
    print(f"  → 評估結果: {level}")

    print()
    print("  LLM 接收到的訊息範例：")
    print(f"  「今日觸發 {today} 次（歷史日均 {mu:.1f} 次、σ={sig:.1f}、z={z:.1f}）」")


# ── 主流程 ────────────────────────────────────────────────────────────────────

async def main() -> None:
    ok = await test_relative()
    if not ok:
        print("\n[ABORT] 基本連線失敗，請確認 API URL / Token 是否正確")
        return

    daily_counts = await test_histogram()

    if daily_counts is None:
        print("\n[結論] histogram API 不可用，需確認 Graylog 版本或改用多次 relative 查詢")
    elif len(daily_counts) == 0:
        print("\n[結論] histogram API 可用，但查詢範圍內無資料（可嘗試換 TEST_QUERY 或縮短 RANGE）")
    else:
        compute_stats(daily_counts)
        print("\n[結論] histogram API 可用 ✓  z-score 方案可以實作")

    print("-" * 60)

asyncio.run(main())
