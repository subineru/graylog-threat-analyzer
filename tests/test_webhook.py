"""
Webhook Server 基本測試

用法：
    pytest tests/test_webhook.py -v
"""

import pytest
from fastapi.testclient import TestClient


# 模擬的 THREAT log（範例資料，非真實環境）
SAMPLE_THREAT_EVENT = {
    "event_definition_id": "test-event-def",
    "event_definition_title": "PA RCVSS High/Medium Alert",
    "event": {
        "id": "test-event-001",
        "timestamp": "2026-04-21T01:53:38.000Z",
    },
    "backlog": [
        {
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
    ],
}

SAMPLE_EMPTY_BACKLOG = {
    "event_definition_id": "test-event-def",
    "event_definition_title": "Test",
    "event": {},
    "backlog": [],
}


class TestEnrichment:
    """測試 enrichment 模組的輔助函式"""

    def test_extract_signature_id(self):
        from src.enrichment import EnrichmentService

        assert EnrichmentService._extract_signature_id("Microsoft Windows NTLMSSP Detection(92322)") == "92322"
        assert EnrichmentService._extract_signature_id("Apache Log4j Remote Code Execution Vulnerability(92001)") == "92001"
        assert EnrichmentService._extract_signature_id("unknown-format") == "unknown-format"

    def test_is_internal(self):
        from src.enrichment import EnrichmentService

        assert EnrichmentService._is_internal("192.168.1.1") is True
        assert EnrichmentService._is_internal("10.0.0.1") is True
        assert EnrichmentService._is_internal("172.16.0.1") is True
        assert EnrichmentService._is_internal("8.8.8.8") is False
        assert EnrichmentService._is_internal("0.0.0.0") is True


class TestEDLEntry:
    """測試 EDL entry 邏輯"""

    def test_entry_creation(self):
        from src.edl_manager import EDLEntry

        entry = EDLEntry(value="1.2.3.4", ttl_days=7)
        assert entry.value == "1.2.3.4"
        assert entry.ttl_days == 7
        assert entry.is_expired is False

    def test_entry_serialization(self):
        from src.edl_manager import EDLEntry

        entry = EDLEntry(value="evil.com", ttl_days=30, source_signature="test")
        d = entry.to_dict()
        restored = EDLEntry.from_dict(d)
        assert restored.value == "evil.com"
        assert restored.ttl_days == 30

    def test_expired_entry(self):
        from src.edl_manager import EDLEntry

        entry = EDLEntry(
            value="1.2.3.4",
            added_at="2020-01-01T00:00:00+00:00",
            ttl_days=1,
        )
        assert entry.is_expired is True


class TestRuleBasedTriage:
    """測試 Phase 1 固定規則研判"""

    def test_blocked_external_attack(self):
        from src.llm_client import LLMClient

        client = LLMClient({"llm": {}})  # 無 LLM 設定，使用固定規則
        enriched = {
            "event_summary": {
                "action": "drop",
                "severity": "critical",
                "source_ip": "45.33.32.156",
                "rcvss": "RCVSS_High",
            },
            "frequency_context": {
                "same_src_same_sig_24h": 10,
                "same_src_other_sig_24h": 0,
                "same_dst_same_sig_24h": 10,
            },
        }
        import asyncio
        verdict = asyncio.run(client.triage(enriched))
        assert verdict.verdict == "false_positive"
        assert verdict.confidence == "high"

    def test_informational_alert(self):
        from src.llm_client import LLMClient

        client = LLMClient({"llm": {}})
        enriched = {
            "event_summary": {
                "action": "alert",
                "severity": "informational",
                "source_ip": "10.0.5.48",
                "rcvss": "RCVSS_Low",
            },
            "frequency_context": {
                "same_src_same_sig_24h": 5,
                "same_src_other_sig_24h": 0,
                "same_dst_same_sig_24h": 5,
            },
        }
        import asyncio
        verdict = asyncio.run(client.triage(enriched))
        assert verdict.verdict == "normal"
