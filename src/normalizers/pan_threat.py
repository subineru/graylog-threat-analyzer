"""
PAN THREAT log 欄位正規化

將 Graylog 解析後的原始欄位名稱對應為 enrichment 所需的統一欄位名稱。

config.example.yaml 中 Graylog JMTE template 建議加入的欄位：
  severity, signature_name, source_zone, destination_zone,
  rule_name, transport, direction

欄位對應關係（Graylog 原始 → 內部統一名稱）：
  alert_signature         → signature_name   (完整 "Name(ID)" 格式)
  vendor_alert_severity   → severity
  alert_signature_id      → signature_id     (純數字 ID)
  network_transport       → transport
  pan_alert_direction     → direction
  source_zone, destination_zone, rule_name, source_ip,
  destination_ip, source_user → 直接保留原欄位名稱
"""

_FIELD_MAP: dict[str, str] = {
    "alert_signature": "signature_name",
    "vendor_alert_severity": "severity",
    "alert_signature_id": "signature_id",
    "network_transport": "transport",
    "pan_alert_direction": "direction",
}

_PASSTHROUGH_FIELDS: set[str] = {
    "source_ip",
    "destination_ip",
    "source_user",
    "source_zone",
    "destination_zone",
    "rule_name",
    "signature_name",
    "severity",
    "signature_id",
    "transport",
    "direction",
}


def normalize(raw: dict) -> dict:
    """將 Graylog raw event 欄位正規化，回傳 enrichment-ready dict。

    - 已知對應欄位優先取 src_key，若不存在則取 dst_key（避免覆蓋已有值）
    - 其餘欄位原樣保留
    """
    out: dict = {}

    for src_key, dst_key in _FIELD_MAP.items():
        val = raw.get(src_key)
        if val is not None and dst_key not in out:
            out[dst_key] = val
        elif raw.get(dst_key) is not None and dst_key not in out:
            out[dst_key] = raw[dst_key]

    for k, v in raw.items():
        if k not in out and k not in _FIELD_MAP:
            out[k] = v

    return out
