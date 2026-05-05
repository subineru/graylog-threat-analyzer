"""
Whitelist Manager 單元測試

覆蓋曾發生的 bug，防止回歸：
- action 語義錯誤：前端傳 triage 動作（investigate）而非 PA 動作（alert）
- src_ip 佔位符 '—' 導致永遠不匹配
- ttl_days 未傳入 suggest_rule / approve_rule 被忽略

用法：
    pytest tests/test_whitelist.py -v
"""

import asyncio
import ipaddress
import os
from datetime import datetime, timezone
import tempfile

import pytest

from src.whitelist_manager import WhitelistManager
from src.expiry_policy import ExpiryPolicy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_manager(csv_content: str = "") -> tuple[WhitelistManager, str]:
    """Create a WhitelistManager backed by a temp CSV file."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8")
    f.write(csv_content)
    f.close()
    wl = WhitelistManager(f.name, default_ttl_days=30)
    wl._rules = []
    wl._pending_rules = {}
    return wl, f.name


def _teardown(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# _parse_networks
# ---------------------------------------------------------------------------

class TestParseNetworks:
    def test_empty_string_returns_wildcard(self):
        assert WhitelistManager._networks_to_str([]) == ""
        assert WhitelistManager._parse_networks("") == []

    def test_none_returns_wildcard(self):
        assert WhitelistManager._parse_networks(None) == []

    def test_valid_ipv4(self):
        nets = WhitelistManager._parse_networks("192.168.1.1")
        assert len(nets) == 1
        assert ipaddress.ip_address("192.168.1.1") in nets[0]

    def test_valid_cidr(self):
        nets = WhitelistManager._parse_networks("10.0.0.0/8")
        assert len(nets) == 1
        assert ipaddress.ip_address("10.1.2.3") in nets[0]

    def test_placeholder_dash_becomes_exact_string(self):
        # '—' cannot be parsed as IP → stored as hostname string.
        # _ip_in_networks will never match a real IP against it.
        nets = WhitelistManager._parse_networks("—")
        assert nets == ["—"]
        assert not WhitelistManager._ip_in_networks("192.168.1.1", nets)

    def test_multiple_ips(self):
        nets = WhitelistManager._parse_networks("10.0.0.1, 10.0.0.2")
        assert len(nets) == 2


# ---------------------------------------------------------------------------
# _matches_rule — action semantics
# ---------------------------------------------------------------------------

class TestMatchesRuleAction:
    """
    Regression: 'action' in known_fp.csv is the PA firewall action (alert/drop/…),
    NOT the triage engine recommendation (investigate/block/monitor/suppress).
    A rule with action='investigate' will never match any real PA event.
    """

    def _rule(self, sig_id, action_set, src_ip=""):
        from src.whitelist_manager import FPRule
        return FPRule(
            signature_id=sig_id,
            signature_name=f"Test Sig ({sig_id})",
            actions=action_set,
            source_networks=WhitelistManager._parse_networks(src_ip),
            destination_networks=[],
            note="test",
            status="monitoring",
            expiry=ExpiryPolicy(ttl_days=90),
        )

    def _summary(self, sig_id, action, src_ip="192.168.1.1"):
        return {"signature_id": sig_id, "action": action, "source_ip": src_ip, "destination_ip": ""}

    def test_pa_action_alert_matches(self):
        wl, path = _make_manager()
        try:
            rule = self._rule("94634", {"alert"})
            wl._rules = [rule]
            assert wl._matches_rule(rule, self._summary("94634", "alert"))
        finally:
            _teardown(path)

    def test_triage_action_investigate_does_not_match_pa_events(self):
        """
        Bug regression: rule with action='investigate' (triage output) must NOT
        match a PA event whose vendor_event_action='alert'.
        """
        wl, path = _make_manager()
        try:
            rule = self._rule("94634", {"investigate"})
            wl._rules = [rule]
            # PA sends action='alert'; rule requires 'investigate' → no match
            assert not wl._matches_rule(rule, self._summary("94634", "alert"))
        finally:
            _teardown(path)

    def test_empty_action_set_matches_any_pa_action(self):
        """
        Fix: addWLFromEvent now sends action='' → empty actions set → wildcard.
        Should match regardless of PA action.
        """
        wl, path = _make_manager()
        try:
            rule = self._rule("94634", set())
            wl._rules = [rule]
            for pa_action in ("alert", "drop", "reset-both", "block-ip"):
                assert wl._matches_rule(rule, self._summary("94634", pa_action)), pa_action
        finally:
            _teardown(path)


# ---------------------------------------------------------------------------
# _matches_rule — src_ip semantics
# ---------------------------------------------------------------------------

class TestMatchesRuleSrcIp:
    def _rule(self, sig_id, src_ip):
        from src.whitelist_manager import FPRule
        return FPRule(
            signature_id=sig_id,
            signature_name="Test",
            actions=set(),
            source_networks=WhitelistManager._parse_networks(src_ip),
            destination_networks=[],
            note="",
            status="monitoring",
            expiry=ExpiryPolicy(ttl_days=90),
        )

    def _summary(self, sig_id, src_ip):
        return {"signature_id": sig_id, "action": "alert", "source_ip": src_ip, "destination_ip": ""}

    def test_real_src_ip_matches(self):
        wl, path = _make_manager()
        try:
            rule = self._rule("31707", "192.168.2.7")
            assert wl._matches_rule(rule, self._summary("31707", "192.168.2.7"))
        finally:
            _teardown(path)

    def test_real_src_ip_does_not_match_other_ip(self):
        wl, path = _make_manager()
        try:
            rule = self._rule("31707", "192.168.2.7")
            assert not wl._matches_rule(rule, self._summary("31707", "192.168.2.8"))
        finally:
            _teardown(path)

    def test_dash_placeholder_never_matches_real_ip(self):
        """
        Bug regression: if frontend sent src_ip='—', rule would never match.
        Fix: frontend now sends src_ip='' for missing IPs → wildcard.
        This test documents the broken behaviour of '—'.
        """
        wl, path = _make_manager()
        try:
            rule = self._rule("31707", "—")
            assert not wl._matches_rule(rule, self._summary("31707", "192.168.2.7"))
        finally:
            _teardown(path)

    def test_empty_src_ip_is_wildcard(self):
        """Empty src_ip in rule matches any source IP."""
        wl, path = _make_manager()
        try:
            rule = self._rule("31707", "")
            assert wl._matches_rule(rule, self._summary("31707", "192.168.2.7"))
            assert wl._matches_rule(rule, self._summary("31707", "10.0.0.1"))
        finally:
            _teardown(path)


# ---------------------------------------------------------------------------
# suggest_rule / approve_rule — ttl_days propagation
# ---------------------------------------------------------------------------

class TestTtlDaysPropagation:
    """
    Bug regression: suggest_rule / approve_rule previously ignored ttl_days,
    always using default_ttl_days from config.
    """

    def test_custom_ttl_days_is_used(self):
        wl, path = _make_manager()
        try:
            token = wl.suggest_rule(
                sig_id="12345", sig_name="Test", action="",
                src_ip="", dst_ip="", note="test", ttl_days=180,
            )
            assert wl._pending_rules[token]["ttl_days"] == 180

            ok, _ = asyncio.run(wl.approve_rule(token))
            assert ok
            assert wl._rules[-1].expiry.ttl_days == 180
        finally:
            _teardown(path)

    def test_none_ttl_falls_back_to_default(self):
        wl, path = _make_manager()
        try:
            token = wl.suggest_rule(
                sig_id="12345", sig_name="Test", action="",
                ttl_days=None,
            )
            ok, _ = asyncio.run(wl.approve_rule(token))
            assert ok
            assert wl._rules[-1].expiry.ttl_days == wl._default_ttl_days
        finally:
            _teardown(path)

    def test_permanent_ttl_minus_one(self):
        wl, path = _make_manager()
        try:
            token = wl.suggest_rule(
                sig_id="12345", sig_name="Test", action="",
                ttl_days=-1,
            )
            ok, _ = asyncio.run(wl.approve_rule(token))
            assert ok
            rule = wl._rules[-1]
            assert rule.expiry.ttl_days == -1
            assert not rule.expiry.is_expired()
        finally:
            _teardown(path)


# ---------------------------------------------------------------------------
# approve_rule — compound-key deduplication
# ---------------------------------------------------------------------------

class TestApproveRuleDedup:
    """
    Regression: approve_rule previously used append-only, allowing the same
    rule to accumulate multiple times (duplicate React keys, wrong hit counts).
    Fix: dedup by (sig_id, src_ip, dst_ip) — exact compound match is replaced,
    same sig_id with different IPs is allowed.
    """

    def _approve(self, wl, sig_id, src_ip="", dst_ip=""):
        token = wl.suggest_rule(sig_id=sig_id, sig_name=f"Sig {sig_id}", action="", src_ip=src_ip, dst_ip=dst_ip)
        return asyncio.run(wl.approve_rule(token))

    def test_approve_same_rule_twice_keeps_one(self):
        """Approving identical (sig_id, src_ip, dst_ip) twice → only one rule survives."""
        wl, path = _make_manager()
        try:
            self._approve(wl, "39154", "192.168.1.1", "")
            self._approve(wl, "39154", "192.168.1.1", "")
            matching = [r for r in wl._rules if r.signature_id == "39154"]
            assert len(matching) == 1
        finally:
            _teardown(path)

    def test_approve_same_sigid_different_src_ip_keeps_both(self):
        """Same sig_id but different src_ip → both rules coexist (multi-host whitelist)."""
        wl, path = _make_manager()
        try:
            self._approve(wl, "39154", "192.168.1.1", "")
            self._approve(wl, "39154", "192.168.2.2", "")
            matching = [r for r in wl._rules if r.signature_id == "39154"]
            assert len(matching) == 2
            src_ips = {WhitelistManager._networks_to_str(r.source_networks) for r in matching}
            assert src_ips == {"192.168.1.1", "192.168.2.2"}
        finally:
            _teardown(path)


# ---------------------------------------------------------------------------
# remove_rule — compound-key precision
# ---------------------------------------------------------------------------

class TestRemoveRule:
    """
    Regression: remove_rule used to delete ALL rules with the same sig_id.
    Fix: when src_ip/dst_ip are provided, only the exact matching rule is removed.
    """

    def _load_two_rules(self, wl):
        """Approve two rules for sig 39154 with different src IPs."""
        for src in ("192.168.1.1", "192.168.2.2"):
            token = wl.suggest_rule(sig_id="39154", sig_name="Test", action="", src_ip=src)
            asyncio.run(wl.approve_rule(token))

    def test_remove_by_compound_key_leaves_other_rule(self):
        """Deleting one (sig_id, src_ip) pair must not remove sibling rules."""
        wl, path = _make_manager()
        try:
            self._load_two_rules(wl)
            assert len([r for r in wl._rules if r.signature_id == "39154"]) == 2

            ok = asyncio.run(wl.remove_rule("39154", src_ip="192.168.1.1", dst_ip=""))
            assert ok
            remaining = [r for r in wl._rules if r.signature_id == "39154"]
            assert len(remaining) == 1
            assert WhitelistManager._networks_to_str(remaining[0].source_networks) == "192.168.2.2"
        finally:
            _teardown(path)

    def test_remove_without_ip_removes_all(self):
        """Omitting src_ip/dst_ip falls back to removing all rules with that sig_id."""
        wl, path = _make_manager()
        try:
            self._load_two_rules(wl)
            ok = asyncio.run(wl.remove_rule("39154"))
            assert ok
            assert not any(r.signature_id == "39154" for r in wl._rules)
        finally:
            _teardown(path)

    def test_remove_nonexistent_returns_false(self):
        wl, path = _make_manager()
        try:
            ok = asyncio.run(wl.remove_rule("99999", src_ip="1.2.3.4", dst_ip=""))
            assert not ok
        finally:
            _teardown(path)


# ---------------------------------------------------------------------------
# sweep — status-aware expiry
# ---------------------------------------------------------------------------

class TestSweepStatus:
    """
    Confirmed rules must survive sweep regardless of TTL expiry.
    Monitoring rules are swept normally when expired.
    """

    def _expired_rule(self, sig_id, status):
        from src.whitelist_manager import FPRule
        from datetime import timedelta
        last = datetime.now(timezone.utc) - timedelta(days=200)
        return FPRule(
            signature_id=sig_id,
            signature_name=f"Sig {sig_id}",
            actions=set(),
            source_networks=[],
            destination_networks=[],
            note="",
            status=status,
            expiry=ExpiryPolicy(ttl_days=90, last_activity=last),
            hit_count=1,
        )

    def test_confirmed_rule_survives_sweep(self):
        """confirmed rules must never be removed by sweep, even when TTL would expire."""
        wl, path = _make_manager()
        try:
            wl._rules = [self._expired_rule("11111", "confirmed")]
            removed = asyncio.run(wl.sweep())
            assert removed == 0
            assert any(r.signature_id == "11111" for r in wl._rules)
        finally:
            _teardown(path)

    def test_monitoring_rule_swept_when_expired(self):
        """monitoring rules are removed by sweep when their TTL window has passed."""
        wl, path = _make_manager()
        try:
            wl._rules = [self._expired_rule("22222", "monitoring")]
            removed = asyncio.run(wl.sweep())
            assert removed == 1
            assert not any(r.signature_id == "22222" for r in wl._rules)
        finally:
            _teardown(path)

    def test_mixed_rules_sweep_only_expired_monitoring(self):
        """Only expired monitoring rules are removed; confirmed and unexpired are kept."""
        wl, path = _make_manager()
        try:
            from src.whitelist_manager import FPRule
            fresh = FPRule(
                signature_id="33333", signature_name="Fresh", actions=set(),
                source_networks=[], destination_networks=[], note="",
                status="monitoring",
                expiry=ExpiryPolicy(ttl_days=90, last_activity=datetime.now(timezone.utc)),
                hit_count=1,
            )
            wl._rules = [
                self._expired_rule("11111", "confirmed"),   # keep
                self._expired_rule("22222", "monitoring"),  # sweep
                fresh,                                       # keep (not expired)
            ]
            removed = asyncio.run(wl.sweep())
            assert removed == 1
            remaining_ids = {r.signature_id for r in wl._rules}
            assert remaining_ids == {"11111", "33333"}
        finally:
            _teardown(path)
