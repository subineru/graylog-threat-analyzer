"""
產生測試 Email HTML 預覽。
用法：python scripts/preview_email.py
輸出：email_preview.html（用瀏覽器開啟檢視）
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.notifier import EmailNotifier
from src.llm_client import TriageVerdict

# 對應 tests/test_webhook.py 的 SAMPLE_THREAT_EVENT
SAMPLE_MESSAGE = {
    "event_log_name": "THREAT",
    "pan_log_subtype": "vulnerability",
    "alert_signature": "Microsoft Windows NTLMSSP Detection(92322)",
    "vendor_event_action": "alert",
    "vendor_alert_severity": "informational",
    "source_ip": "10.0.5.48",
    "destination_ip": "10.0.1.10",
    "source_user_name": "CORP\\user01",
    "destination_user_name": "CORP\\svc_admin",
    "application_name": "msrpc-base",
    "network_transport": "tcp",
    "pan_alert_direction": "client-to-server",
    "source_zone": "Untrust-VPN",
    "destination_zone": "Trust",
    "rule_name": "VPN-to-Internal",
    "RCVSS": "RCVSS_Low",
    "event_uid": "1234567890123456789",
}

MOCK_ENRICHED = {
    "event_summary": {
        "signature_id": "92322",
        "signature_name": "Microsoft Windows NTLMSSP Detection(92322)",
        "severity": "informational",
        "action": "alert",
        "source_ip": "10.0.5.48",
        "source_user": "CORP\\user01",
        "destination_ip": "10.0.1.10",
        "destination_user": "CORP\\svc_admin",
        "protocol": "msrpc-base / tcp",
        "direction": "client-to-server",
        "zone_flow": "Untrust-VPN → Trust",
        "rule_name": "VPN-to-Internal",
        "rcvss": "RCVSS_Low",
    },
    "asset_context": {
        "source_asset": {
            "hostname": "unknown",
            "role": "user-endpoint",
            "department": "unknown",
            "note": "",
        },
        "destination_asset": {
            "hostname": "dc01",
            "role": "domain-controller",
            "department": "IT",
            "note": "AD",
        },
    },
    "frequency_context": {
        "same_src_same_sig_24h": 12,
        "same_src_other_sig_24h": 3,
        "same_dst_same_sig_24h": 47,
    },
    "threat_intel": {
        "source_ip_reputation": "N/A (internal)",
        "destination_ip_reputation": "N/A (internal)",
    },
    "raw_message": SAMPLE_MESSAGE,
}

MOCK_VERDICT = TriageVerdict(
    verdict="anomalous",
    confidence="high",
    reasoning="來源 IP 10.0.5.48 於過去 24 小時內觸發 12 次相同 signature，且為未知裝置（不在資產清冊中）。目標為 AD 網域控制站，存在橫向移動風險，建議封鎖。",
    recommended_action="block",
    edl_entry="10.0.5.48",
)

MOCK_APPROVE_URL = "http://localhost:8000/edl/approve/a1b2c3d4-e5f6-7890-abcd-ef1234567890"

if __name__ == "__main__":
    notifier = EmailNotifier({})
    html = notifier._format_email_body(MOCK_ENRICHED, MOCK_VERDICT, edl_approve_url=MOCK_APPROVE_URL)
    out = Path("email_preview.html")
    out.write_text(html, encoding="utf-8")
    print(f"Email preview saved to: {out.resolve()}")
    print("請用瀏覽器開啟 email_preview.html 檢視格式。")
