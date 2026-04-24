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
        from src.graylog_client import GraylogClient

        assert GraylogClient._extract_signature_id("Microsoft Windows NTLMSSP Detection(92322)") == "92322"
        assert GraylogClient._extract_signature_id("Apache Log4j Remote Code Execution Vulnerability(92001)") == "92001"
        assert GraylogClient._extract_signature_id("unknown-format") == "unknown-format"

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
    """測試 Gate 3 固定規則研判（透過 TriageEngine）"""

    def test_blocked_external_attack(self):
        from src.triage_engine import TriageEngine
        import asyncio

        engine = TriageEngine({"llm": {}})
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
        verdict = asyncio.run(engine.triage(enriched))
        assert verdict.verdict == "false_positive"
        assert verdict.confidence == "high"

    def test_informational_alert(self):
        from src.triage_engine import TriageEngine
        import asyncio

        engine = TriageEngine({"llm": {}})
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
        verdict = asyncio.run(engine.triage(enriched))
        assert verdict.verdict == "normal"

    def test_ntlmssp_from_known_endpoint_to_dc(self):
        from src.triage_engine import TriageEngine
        import asyncio

        engine = TriageEngine({"llm": {}})
        enriched = {
            "event_summary": {
                "action": "alert",
                "severity": "medium",
                "source_ip": "10.0.5.48",
                "signature_name": "Microsoft Windows NTLMSSP Detection(92322)",
            },
            "asset_context": {
                "source_asset": {"hostname": "laptop01", "role": "user-endpoint", "department": "IT"},
                "destination_asset": {"hostname": "dc01", "role": "domain-controller", "department": "IT"},
            },
            "frequency_context": {"same_src_same_sig_24h": 3, "same_src_other_sig_24h": 0, "same_dst_same_sig_24h": 20},
        }
        verdict = asyncio.run(engine.triage(enriched))
        assert verdict.verdict == "normal"
        assert verdict.confidence == "high"

    def test_unknown_external_ip(self):
        from src.triage_engine import TriageEngine
        import asyncio

        engine = TriageEngine({"llm": {}})
        enriched = {
            "event_summary": {
                "action": "alert",
                "severity": "high",
                "source_ip": "45.33.32.156",
                "signature_name": "Port Scan Detected(12345)",
            },
            "asset_context": {
                "source_asset": {"hostname": "unknown", "role": "unknown", "department": "unknown"},
                "destination_asset": {"hostname": "web01", "role": "web-server", "department": "IT"},
            },
            "frequency_context": {"same_src_same_sig_24h": 1, "same_src_other_sig_24h": 2, "same_dst_same_sig_24h": 1},
        }
        verdict = asyncio.run(engine.triage(enriched))
        assert verdict.verdict == "anomalous"
        assert verdict.confidence == "high"
        assert verdict.edl_entry == "45.33.32.156"

    def test_unknown_internal_ip(self):
        from src.triage_engine import TriageEngine
        import asyncio

        engine = TriageEngine({"llm": {}})
        enriched = {
            "event_summary": {
                "action": "alert",
                "severity": "medium",
                "source_ip": "10.0.99.99",
                "signature_name": "SQL Injection Attempt(55123)",
            },
            "asset_context": {
                "source_asset": {"hostname": "unknown", "role": "unknown", "department": "unknown"},
                "destination_asset": {"hostname": "db01", "role": "database-server", "department": "ENG"},
            },
            "frequency_context": {"same_src_same_sig_24h": 5, "same_src_other_sig_24h": 1, "same_dst_same_sig_24h": 5},
        }
        verdict = asyncio.run(engine.triage(enriched))
        assert verdict.verdict == "anomalous"
        assert verdict.confidence == "medium"
        assert verdict.edl_entry is None


class TestEDLApproval:
    """測試 EDL pending 佇列與 approval 機制"""

    def test_suggest_creates_pending_entry(self, tmp_path):
        from src.edl_manager import EDLManager

        mgr = EDLManager({"edl": {"output_dir": str(tmp_path), "default_ttl_days": 30}})
        token = mgr.suggest_entry("1.2.3.4", source_event={"alert_signature": "Test(999)", "event_uid": "uid-001"})
        assert token
        pending = mgr.list_pending()
        assert len(pending) == 1
        assert pending[0]["value"] == "1.2.3.4"
        assert pending[0]["token"] == token

    def test_suggest_deduplicates(self, tmp_path):
        from src.edl_manager import EDLManager

        mgr = EDLManager({"edl": {"output_dir": str(tmp_path), "default_ttl_days": 30}})
        token1 = mgr.suggest_entry("1.2.3.4")
        token2 = mgr.suggest_entry("1.2.3.4")
        assert token1 == token2
        assert len(mgr.list_pending()) == 1

    def test_approve_writes_to_edl(self, tmp_path):
        from src.edl_manager import EDLManager

        mgr = EDLManager({"edl": {"output_dir": str(tmp_path), "default_ttl_days": 30}})
        token = mgr.suggest_entry("5.6.7.8")
        success, msg = mgr.approve_entry(token)
        assert success is True
        assert len(mgr.list_entries()) == 1
        assert mgr.list_entries()[0]["value"] == "5.6.7.8"
        assert len(mgr.list_pending()) == 0

    def test_approve_invalid_token(self, tmp_path):
        from src.edl_manager import EDLManager

        mgr = EDLManager({"edl": {"output_dir": str(tmp_path), "default_ttl_days": 30}})
        success, msg = mgr.approve_entry("nonexistent-token")
        assert success is False

    def test_reject_entry(self, tmp_path):
        from src.edl_manager import EDLManager

        mgr = EDLManager({"edl": {"output_dir": str(tmp_path), "default_ttl_days": 30}})
        token = mgr.suggest_entry("9.10.11.12")
        success, msg = mgr.reject_entry(token)
        assert success is True
        assert len(mgr.list_pending()) == 0
        assert len(mgr.list_entries()) == 0


class TestKnownFP:
    """測試 known_fp.csv 快速過濾邏輯"""

    CSV_CONTENT = (
        "signature_id,signature_name,action,source_ip,destination_ip,rcvss,note\n"
        '92322,Microsoft Windows NTLMSSP Detection,alert,,"192.168.2.7,192.168.2.8",None,AD 正常 NTLM 認證\n'
    )

    def _make_checker(self, tmp_path):
        from src.known_fp import KnownFPChecker
        csv_file = tmp_path / "known_fp.csv"
        csv_file.write_text(self.CSV_CONTENT, encoding="utf-8")
        return KnownFPChecker(str(csv_file))

    def test_ntlmssp_to_ad_ip_matches(self, tmp_path):
        checker = self._make_checker(tmp_path)
        result = checker.check({
            "signature_id": "92322",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "192.168.2.7",
        })
        assert result == "AD 正常 NTLM 認證"

    def test_same_sig_unknown_dst_no_match(self, tmp_path):
        checker = self._make_checker(tmp_path)
        result = checker.check({
            "signature_id": "92322",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "10.0.99.99",
        })
        assert result is None

    def test_different_sig_no_match(self, tmp_path):
        checker = self._make_checker(tmp_path)
        result = checker.check({
            "signature_id": "12345",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "192.168.2.7",
        })
        assert result is None

    def test_full_signature_name_extracted(self, tmp_path):
        checker = self._make_checker(tmp_path)
        result = checker.check({
            "signature_id": "",
            "signature_name": "Microsoft Windows NTLMSSP Detection(92322)",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "192.168.2.8",
        })
        assert result == "AD 正常 NTLM 認證"

    def test_triage_returns_false_positive(self, tmp_path):
        from src.triage_engine import TriageEngine
        import asyncio

        csv_file = tmp_path / "known_fp.csv"
        csv_file.write_text(self.CSV_CONTENT, encoding="utf-8")
        engine = TriageEngine({"llm": {}, "known_fp": {"csv_path": str(csv_file)}})
        enriched = {
            "event_summary": {
                "signature_id": "92322",
                "signature_name": "Microsoft Windows NTLMSSP Detection(92322)",
                "action": "alert",
                "source_ip": "10.0.5.48",
                "destination_ip": "192.168.2.7",
            }
        }
        verdict = asyncio.run(engine.triage(enriched))
        assert verdict.verdict == "false_positive"
        assert verdict.confidence == "high"
        assert verdict.recommended_action == "suppress"


class TestKnownFPCIDR:
    """測試 known_fp.csv CIDR 網段比對"""

    CSV_CIDR = (
        "signature_id,signature_name,action,source_ip,destination_ip,rcvss,note\n"
        "92322,Microsoft Windows NTLMSSP Detection,alert,,192.168.2.0/24,None,AD 伺服器網段\n"
    )

    def _make_checker(self, tmp_path):
        from src.known_fp import KnownFPChecker
        csv_file = tmp_path / "known_fp_cidr.csv"
        csv_file.write_text(self.CSV_CIDR, encoding="utf-8")
        return KnownFPChecker(str(csv_file))

    def test_ip_in_cidr_matches(self, tmp_path):
        checker = self._make_checker(tmp_path)
        result = checker.check({
            "signature_id": "92322",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "192.168.2.100",
        })
        assert result == "AD 伺服器網段"

    def test_ip_out_of_cidr_no_match(self, tmp_path):
        checker = self._make_checker(tmp_path)
        result = checker.check({
            "signature_id": "92322",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "192.168.3.1",
        })
        assert result is None

    def test_cidr_boundary_last_host_matches(self, tmp_path):
        checker = self._make_checker(tmp_path)
        result = checker.check({
            "signature_id": "92322",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "192.168.2.255",
        })
        assert result == "AD 伺服器網段"

    def test_mixed_ip_and_cidr(self, tmp_path):
        """同一規則混用單一 IP 與 CIDR"""
        from src.known_fp import KnownFPChecker
        csv_content = (
            "signature_id,signature_name,action,source_ip,destination_ip,rcvss,note\n"
            '"92322","Microsoft Windows NTLMSSP Detection","alert",,"10.0.1.5,192.168.2.0/24","None","混合規則"\n'
        )
        csv_file = tmp_path / "known_fp_mixed.csv"
        csv_file.write_text(csv_content, encoding="utf-8")
        checker = KnownFPChecker(str(csv_file))

        assert checker.check({"signature_id": "92322", "action": "alert",
                               "source_ip": "", "destination_ip": "10.0.1.5"}) == "混合規則"
        assert checker.check({"signature_id": "92322", "action": "alert",
                               "source_ip": "", "destination_ip": "192.168.2.200"}) == "混合規則"
        assert checker.check({"signature_id": "92322", "action": "alert",
                               "source_ip": "", "destination_ip": "10.0.2.1"}) is None


class TestRateLimiter:
    """測試 Rate Limiter 去重邏輯"""

    def test_first_event_not_duplicate(self):
        from src.rate_limiter import RateLimiter

        rl = RateLimiter(window_seconds=900)
        is_dup, count = rl.check_and_record("10.0.0.1", "92322")
        assert is_dup is False
        assert count == 1

    def test_second_event_is_duplicate(self):
        from src.rate_limiter import RateLimiter

        rl = RateLimiter(window_seconds=900)
        rl.check_and_record("10.0.0.1", "92322")
        is_dup, count = rl.check_and_record("10.0.0.1", "92322")
        assert is_dup is True
        assert count == 2

    def test_different_sig_not_duplicate(self):
        from src.rate_limiter import RateLimiter

        rl = RateLimiter(window_seconds=900)
        rl.check_and_record("10.0.0.1", "92322")
        is_dup, count = rl.check_and_record("10.0.0.1", "99999")
        assert is_dup is False

    def test_different_ip_not_duplicate(self):
        from src.rate_limiter import RateLimiter

        rl = RateLimiter(window_seconds=900)
        rl.check_and_record("10.0.0.1", "92322")
        is_dup, count = rl.check_and_record("10.0.0.2", "92322")
        assert is_dup is False

    def test_duplicate_suppressed_in_triage(self):
        from src.triage_engine import TriageEngine
        import asyncio

        engine = TriageEngine({"llm": {}})
        enriched = {
            "event_summary": {
                "action": "alert",
                "severity": "high",
                "source_ip": "10.0.5.99",
                "signature_id": "77777",
                "signature_name": "Duplicate Test(77777)",
            },
            "asset_context": {},
            "frequency_context": {},
        }

        async def run_twice():
            await engine.triage(enriched)          # 第一次：正常處理
            return await engine.triage(enriched)   # 第二次：應被抑制

        verdict = asyncio.run(run_twice())
        assert verdict.verdict == "duplicate"
        assert verdict.recommended_action == "suppress"
