"""
Webhook Server 基本測試

用法：
    pytest tests/test_webhook.py -v
"""

import asyncio
from datetime import datetime, timedelta, timezone

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


class TestExpiryPolicy:
    """測試共用 TTL 邏輯"""

    def test_permanent(self):
        from src.expiry_policy import ExpiryPolicy

        policy = ExpiryPolicy(ttl_days=-1, last_activity=datetime(2000, 1, 1, tzinfo=timezone.utc))
        assert policy.is_expired() is False

    def test_expired(self):
        from src.expiry_policy import ExpiryPolicy

        old = datetime.now(timezone.utc) - timedelta(days=100)
        policy = ExpiryPolicy(ttl_days=30, last_activity=old)
        assert policy.is_expired() is True

    def test_not_expired(self):
        from src.expiry_policy import ExpiryPolicy

        recent = datetime.now(timezone.utc) - timedelta(days=1)
        policy = ExpiryPolicy(ttl_days=30, last_activity=recent)
        assert policy.is_expired() is False

    def test_never_hit_not_expired(self):
        from src.expiry_policy import ExpiryPolicy

        policy = ExpiryPolicy(ttl_days=30, last_activity=None)
        assert policy.is_expired() is False


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

    def test_classify_entry(self):
        from src.edl_manager import EDLManager

        assert EDLManager.classify_entry("1.2.3.4") == "ip"
        assert EDLManager.classify_entry("10.0.0.0/8") == "ip"
        assert EDLManager.classify_entry("http://evil.com/payload") == "url"
        assert EDLManager.classify_entry("*.malware.cn") == "url"
        assert EDLManager.classify_entry("evil.com") == "domain"

    def test_entry_type_auto_classified(self):
        from src.edl_manager import EDLEntry

        assert EDLEntry(value="1.2.3.4").entry_type == "ip"
        assert EDLEntry(value="http://evil.com").entry_type == "url"
        assert EDLEntry(value="evil.com").entry_type == "domain"

    def test_sliding_window_resets_ttl(self, tmp_path):
        from src.edl_manager import EDLManager

        mgr = EDLManager({"edl": {"output_dir": str(tmp_path), "default_ttl_days": 30}})
        mgr.add_entry("5.5.5.5")
        before = mgr._entries[0].expiry.last_activity

        import time
        time.sleep(0.01)
        mgr.add_entry("5.5.5.5")   # should slide window
        after = mgr._entries[0].expiry.last_activity

        assert after > before

    def test_update_entry_ttl_to_permanent(self, tmp_path):
        from src.edl_manager import EDLManager

        mgr = EDLManager({"edl": {"output_dir": str(tmp_path), "default_ttl_days": 30}})
        mgr.add_entry("9.9.9.9")
        ok = mgr.update_entry_ttl("9.9.9.9", -1)
        assert ok is True
        assert mgr._entries[0].expiry.ttl_days == -1
        assert mgr._entries[0].is_expired is False


class TestRuleBasedTriage:
    """測試 Gate 3 固定規則研判（透過 TriageEngine）"""

    def test_blocked_external_attack(self):
        from src.triage_engine import TriageEngine

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


# ---------------------------------------------------------------------------
# TestWhitelistManager — 使用新 CSV schema
# ---------------------------------------------------------------------------

# 最小可用 CSV：包含新欄位但舊欄位（rcvss）被省略
_WL_CSV = (
    "signature_id,signature_name,action,source_ip,destination_ip,"
    "note,status,ttl_days,last_hit_time,hit_count\n"
    '92322,Microsoft Windows NTLMSSP Detection,alert,,"192.168.2.7,192.168.2.8",'
    "AD 正常 NTLM 認證,confirmed,,,0\n"
)

_WL_CSV_CIDR = (
    "signature_id,signature_name,action,source_ip,destination_ip,"
    "note,status,ttl_days,last_hit_time,hit_count\n"
    "92322,Microsoft Windows NTLMSSP Detection,alert,,192.168.2.0/24,"
    "AD 伺服器網段,confirmed,,,0\n"
)


def _make_manager(tmp_path, content=_WL_CSV, default_ttl=90):
    from src.whitelist_manager import WhitelistManager
    csv_file = tmp_path / "wl.csv"
    csv_file.write_text(content, encoding="utf-8")
    return WhitelistManager(str(csv_file), default_ttl_days=default_ttl)


class TestWhitelistManager:
    """測試白名單命中追蹤、TTL sweep、write_back"""

    def test_ntlmssp_to_ad_ip_matches(self, tmp_path):
        manager = _make_manager(tmp_path)
        result = asyncio.run(manager.check({
            "signature_id": "92322",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "192.168.2.7",
        }))
        assert result == "AD 正常 NTLM 認證"

    def test_same_sig_unknown_dst_no_match(self, tmp_path):
        manager = _make_manager(tmp_path)
        result = asyncio.run(manager.check({
            "signature_id": "92322",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "10.0.99.99",
        }))
        assert result is None

    def test_different_sig_no_match(self, tmp_path):
        manager = _make_manager(tmp_path)
        result = asyncio.run(manager.check({
            "signature_id": "12345",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "192.168.2.7",
        }))
        assert result is None

    def test_full_signature_name_extracted(self, tmp_path):
        manager = _make_manager(tmp_path)
        result = asyncio.run(manager.check({
            "signature_id": "",
            "signature_name": "Microsoft Windows NTLMSSP Detection(92322)",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "192.168.2.8",
        }))
        assert result == "AD 正常 NTLM 認證"

    def test_hit_count_increments(self, tmp_path):
        manager = _make_manager(tmp_path)
        summary = {
            "signature_id": "92322",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "192.168.2.7",
        }

        async def run():
            await manager.check(summary)
            await manager.check(summary)
            return manager._rules[0].hit_count

        count = asyncio.run(run())
        assert count == 2

    def test_last_hit_time_updated(self, tmp_path):
        manager = _make_manager(tmp_path)
        assert manager._rules[0].expiry.last_activity is None

        asyncio.run(manager.check({
            "signature_id": "92322",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "192.168.2.7",
        }))
        assert manager._rules[0].expiry.last_activity is not None

    def test_sweep_removes_stale(self, tmp_path):
        from src.whitelist_manager import WhitelistManager
        old_ts = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        csv_content = (
            "signature_id,signature_name,action,source_ip,destination_ip,"
            "note,status,ttl_days,last_hit_time,hit_count\n"
            f"92322,NTLMSSP,alert,,,stale rule,confirmed,30,{old_ts},5\n"
        )
        csv_file = tmp_path / "wl_stale.csv"
        csv_file.write_text(csv_content, encoding="utf-8")
        manager = WhitelistManager(str(csv_file), default_ttl_days=30)
        assert len(manager._rules) == 1

        removed = asyncio.run(manager.sweep())
        assert removed == 1
        assert len(manager._rules) == 0

    def test_sweep_keeps_never_hit(self, tmp_path):
        manager = _make_manager(tmp_path)  # last_hit_time is empty → never hit
        removed = asyncio.run(manager.sweep())
        assert removed == 0
        assert len(manager._rules) == 1

    def test_sweep_keeps_permanent(self, tmp_path):
        from src.whitelist_manager import WhitelistManager
        old_ts = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        csv_content = (
            "signature_id,signature_name,action,source_ip,destination_ip,"
            "note,status,ttl_days,last_hit_time,hit_count\n"
            f"92322,NTLMSSP,alert,,,permanent rule,confirmed,-1,{old_ts},99\n"
        )
        csv_file = tmp_path / "wl_perm.csv"
        csv_file.write_text(csv_content, encoding="utf-8")
        manager = WhitelistManager(str(csv_file), default_ttl_days=30)

        removed = asyncio.run(manager.sweep())
        assert removed == 0

    def test_write_back_roundtrip(self, tmp_path):
        manager = _make_manager(tmp_path)
        summary = {
            "signature_id": "92322",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "192.168.2.7",
        }

        async def run():
            await manager.check(summary)
            await manager.write_back()
            await manager.reload()

        asyncio.run(run())
        assert len(manager._rules) == 1
        assert manager._rules[0].hit_count == 1
        assert manager._rules[0].expiry.last_activity is not None

    def test_triage_returns_false_positive(self, tmp_path):
        from src.triage_engine import TriageEngine

        csv_file = tmp_path / "known_fp.csv"
        csv_file.write_text(_WL_CSV, encoding="utf-8")
        engine = TriageEngine({"llm": {}, "whitelist": {"csv_path": str(csv_file)}})
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
        assert verdict.stage == "whitelist"


class TestWhitelistManagerCIDR:
    """測試 CIDR 網段比對"""

    def test_ip_in_cidr_matches(self, tmp_path):
        manager = _make_manager(tmp_path, _WL_CSV_CIDR)
        result = asyncio.run(manager.check({
            "signature_id": "92322",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "192.168.2.100",
        }))
        assert result == "AD 伺服器網段"

    def test_ip_out_of_cidr_no_match(self, tmp_path):
        manager = _make_manager(tmp_path, _WL_CSV_CIDR)
        result = asyncio.run(manager.check({
            "signature_id": "92322",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "192.168.3.1",
        }))
        assert result is None

    def test_cidr_boundary_last_host_matches(self, tmp_path):
        manager = _make_manager(tmp_path, _WL_CSV_CIDR)
        result = asyncio.run(manager.check({
            "signature_id": "92322",
            "action": "alert",
            "source_ip": "10.0.5.48",
            "destination_ip": "192.168.2.255",
        }))
        assert result == "AD 伺服器網段"

    def test_mixed_ip_and_cidr(self, tmp_path):
        from src.whitelist_manager import WhitelistManager
        csv_content = (
            "signature_id,signature_name,action,source_ip,destination_ip,"
            "note,status,ttl_days,last_hit_time,hit_count\n"
            '"92322","NTLMSSP","alert",,"10.0.1.5,192.168.2.0/24","混合規則",confirmed,,,0\n'
        )
        csv_file = tmp_path / "wl_mixed.csv"
        csv_file.write_text(csv_content, encoding="utf-8")
        manager = WhitelistManager(str(csv_file))

        assert asyncio.run(manager.check({
            "signature_id": "92322", "action": "alert",
            "source_ip": "", "destination_ip": "10.0.1.5",
        })) == "混合規則"
        assert asyncio.run(manager.check({
            "signature_id": "92322", "action": "alert",
            "source_ip": "", "destination_ip": "192.168.2.200",
        })) == "混合規則"
        assert asyncio.run(manager.check({
            "signature_id": "92322", "action": "alert",
            "source_ip": "", "destination_ip": "10.0.2.1",
        })) is None


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
        assert verdict.stage == "rate_limit"


class TestSafeAudit:
    """測試每日 JSONL 稽核寫入與匯出"""

    def _make_verdict(self):
        from src.llm_client import TriageVerdict
        return TriageVerdict(
            verdict="anomalous",
            confidence="high",
            reasoning="Test reasoning",
            recommended_action="block",
            stage="gate3_rule",
        )

    def _make_enriched(self):
        return {
            "event_summary": {
                "source_ip": "1.2.3.4",
                "destination_ip": "10.0.1.5",
                "signature_id": "12345",
                "signature_name": "Test Sig(12345)",
            }
        }

    def test_record_creates_jsonl(self, tmp_path):
        from src.safe_audit import SafeAudit
        import json
        from datetime import date

        audit = SafeAudit(str(tmp_path))
        asyncio.run(audit.record(self._make_enriched(), self._make_verdict(), "gate3_rule"))

        today_file = tmp_path / f"{date.today()}.jsonl"
        assert today_file.exists()
        line = today_file.read_text(encoding="utf-8").strip()
        parsed = json.loads(line)
        assert parsed["stage"] == "gate3_rule"

    def test_record_fields_present(self, tmp_path):
        from src.safe_audit import SafeAudit
        import json

        audit = SafeAudit(str(tmp_path))
        asyncio.run(audit.record(self._make_enriched(), self._make_verdict(), "gate3_rule"))

        path = audit._today_path()
        rec = json.loads(path.read_text(encoding="utf-8").strip())
        assert "timestamp" in rec
        assert "stage" in rec
        assert "verdict" in rec
        assert "event_summary" in rec
        assert rec["verdict"]["verdict"] == "anomalous"
        assert rec["event_summary"]["source_ip"] == "1.2.3.4"

    def test_export_csv_columns(self, tmp_path):
        from src.safe_audit import SafeAudit
        from datetime import date

        audit = SafeAudit(str(tmp_path))
        asyncio.run(audit.record(self._make_enriched(), self._make_verdict(), "gate3_rule"))

        csv_str = audit.export_csv(str(date.today()))
        assert csv_str is not None
        header = csv_str.splitlines()[0]
        for col in ("timestamp", "stage", "verdict", "confidence", "src_ip", "dst_ip"):
            assert col in header

    def test_export_returns_none_for_missing_date(self, tmp_path):
        from src.safe_audit import SafeAudit

        audit = SafeAudit(str(tmp_path))
        assert audit.export_csv("1999-01-01") is None
        assert audit.export_jsonl("1999-01-01") is None
