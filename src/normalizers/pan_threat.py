"""
PAN THREAT log 欄位正規化

將 Graylog 解析後的原始欄位名稱對應為 enrichment 所需的統一欄位名稱。
非破壞性：原始欄位全部保留，另新增正規化名稱作為 alias。

欄位對應關係（Graylog 原始 → 內部統一名稱）：
  alert_signature         → signature_name   (完整 "Name(ID)" 格式)
  vendor_alert_severity   → severity
  alert_signature_id      → signature_id     (純數字 ID)
  network_transport       → transport
  pan_alert_direction     → direction
"""

_FIELD_MAP: dict[str, str] = {
    "alert_signature": "signature_name",
    "vendor_alert_severity": "severity",
    "alert_signature_id": "signature_id",
    "network_transport": "transport",
    "pan_alert_direction": "direction",
}


def normalize(raw: dict) -> dict:
    """將 Graylog raw event 欄位正規化，回傳 enrichment-ready dict。

    非破壞性：原始欄位一律保留，僅在目標欄位尚未存在時補上 alias。
    例：alert_signature 存在且 signature_name 不存在 → 新增 signature_name。
    """
    out = dict(raw)
    for src_key, dst_key in _FIELD_MAP.items():
        val = raw.get(src_key)
        if val is not None and dst_key not in raw:
            out[dst_key] = val
    return out
