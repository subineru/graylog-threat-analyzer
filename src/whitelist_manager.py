"""
Whitelist Manager

取代 known_fp.py，新增：
- hit tracking（last_hit_time、hit_count）
- TTL sliding window sweep（TTL = -1 永不過期）
- asyncio.Lock 並發保護
- 原子寫回 CSV（os.replace）
- hot-reload via reload()

CSV schema:
  signature_id, signature_name, action, source_ip, destination_ip,
  note, status, ttl_days, last_hit_time, hit_count
"""

import asyncio
import csv
import ipaddress
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from .expiry_policy import ExpiryPolicy

logger = logging.getLogger(__name__)

CSV_COLUMNS = [
    "signature_id", "signature_name", "action",
    "source_ip", "destination_ip",
    "note", "status", "ttl_days", "last_hit_time", "hit_count",
]


@dataclass
class FPRule:
    signature_id: str
    signature_name: str
    actions: set                  # parsed from "action" column
    source_networks: list         # list[IPv4Network | str]
    destination_networks: list
    note: str
    status: str                   # confirmed | monitoring
    expiry: ExpiryPolicy          # ttl_days + last_activity (= last_hit_time)
    hit_count: int = field(default=0)


class WhitelistManager:
    def __init__(self, csv_path: str, default_ttl_days: int = 90, sweep_interval: int = 300):
        self._csv_path = csv_path
        self._default_ttl_days = default_ttl_days
        self._sweep_interval = sweep_interval
        self._rules: list[FPRule] = []
        self._lock = asyncio.Lock()
        self._sweeper_task: asyncio.Task | None = None
        self._pending_rules: dict[str, dict] = {}  # token → rule_data
        self._load(csv_path)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self, csv_path: str) -> None:
        path = Path(csv_path)
        if not path.exists():
            logger.warning(f"Whitelist CSV not found: {csv_path}")
            return
        with open(path, "r", encoding="utf-8") as f:
            lines = [ln for ln in f if not ln.startswith("#")]
        reader = csv.DictReader(lines)
        rules: list[FPRule] = []
        for row in reader:
            actions = {a.strip() for a in (row.get("action") or "").split(",") if a.strip()}

            ttl_raw = (row.get("ttl_days") or "").strip()
            ttl_days = int(ttl_raw) if ttl_raw else self._default_ttl_days

            lht_raw = (row.get("last_hit_time") or "").strip()
            last_activity = datetime.fromisoformat(lht_raw) if lht_raw else None

            hit_raw = (row.get("hit_count") or "").strip()
            hit_count = int(hit_raw) if hit_raw else 0

            rules.append(FPRule(
                signature_id=(row.get("signature_id") or "").strip(),
                signature_name=(row.get("signature_name") or "").strip(),
                actions=actions,
                source_networks=self._parse_networks(row.get("source_ip")),
                destination_networks=self._parse_networks(row.get("destination_ip")),
                note=(row.get("note") or "").strip(),
                status=(row.get("status") or "confirmed").strip(),
                expiry=ExpiryPolicy(ttl_days=ttl_days, last_activity=last_activity),
                hit_count=hit_count,
            ))
        self._rules = rules
        self._rules = self._dedup_rules(self._rules)
        logger.info(f"Loaded {len(self._rules)} whitelist rules from {csv_path}")

    # ------------------------------------------------------------------
    # Matching helpers (ported from known_fp.py)
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_networks(raw: Any) -> list:
        """Parse comma-separated IPs / CIDRs. Empty or 'any' → wildcard (empty list)."""
        if not raw:
            return []
        networks = []
        for item in str(raw).split(","):
            item = item.strip()
            if not item or item.lower() in ("any", "none"):
                continue
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                networks.append(item)   # hostname → exact-string fallback
        return networks

    @staticmethod
    def _ip_in_networks(ip_str: str, networks: list) -> bool:
        """Empty networks = wildcard (True). Check IP against network list."""
        if not networks:
            return True
        for net in networks:
            if isinstance(net, str):
                if ip_str == net:
                    return True
            else:
                try:
                    if ipaddress.ip_address(ip_str) in net:
                        return True
                except ValueError:
                    pass
        return False

    def _dedup_rules(self, rules: list) -> list:
        """Keep last occurrence of each (sig_id, src_ip, dst_ip) triple."""
        seen: dict[tuple, int] = {}
        for i, r in enumerate(rules):
            key = (r.signature_id,
                   self._networks_to_str(r.source_networks),
                   self._networks_to_str(r.destination_networks))
            seen[key] = i
        return [rules[i] for i in sorted(seen.values())]

    @staticmethod
    def _extract_sig_id(signature: str) -> str:
        """Extract ID from 'Name(ID)' format, or return as-is."""
        if "(" in signature and signature.endswith(")"):
            return signature.rsplit("(", 1)[-1].rstrip(")")
        return signature

    def _matches_rule(self, rule: FPRule, summary: dict) -> bool:
        sig_id = self._extract_sig_id(
            summary.get("signature_id", "") or summary.get("signature_name", "")
        )
        if rule.signature_id != sig_id:
            return False
        action = summary.get("action", "")
        if rule.actions and action not in rule.actions:
            return False
        if not self._ip_in_networks(summary.get("source_ip", ""), rule.source_networks):
            return False
        if not self._ip_in_networks(summary.get("destination_ip", ""), rule.destination_networks):
            return False
        return True

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def check(self, summary: dict) -> str | None:
        """
        Match event summary against whitelist rules.
        On hit: update last_hit_time + hit_count, return rule note.
        Returns None if no rule matches.
        """
        async with self._lock:
            for rule in self._rules:
                if self._matches_rule(rule, summary):
                    rule.expiry.touch()
                    rule.hit_count += 1
                    note = rule.note or rule.signature_name
                    logger.debug(f"Whitelist match: {note} (hit_count={rule.hit_count})")
                    return note
        return None

    async def sweep(self) -> int:
        """Remove expired monitoring rules. Confirmed rules are never swept."""
        async with self._lock:
            before = len(self._rules)
            self._rules = [
                r for r in self._rules
                if r.status == 'confirmed' or not r.expiry.is_expired()
            ]
            removed = before - len(self._rules)
        if removed:
            logger.info(f"Whitelist sweep: removed {removed} stale rules")
        return removed

    async def write_back(self) -> None:
        """Atomically write current rules back to CSV using os.replace."""
        async with self._lock:
            snapshot = list(self._rules)

        tmp_path = self._csv_path + ".tmp"
        snapshot.sort(key=lambda r: (
            r.signature_id,
            self._networks_to_str(r.source_networks),
            self._networks_to_str(r.destination_networks),
        ))
        with open(tmp_path, "w", encoding="utf-8", newline="") as f:
            f.write("# 已知誤判清單 — 由 WhitelistManager 自動維護，可直接編輯後 POST /whitelist/reload\n")
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            for rule in snapshot:
                la = rule.expiry.last_activity
                writer.writerow({
                    "signature_id":    rule.signature_id,
                    "signature_name":  rule.signature_name,
                    "action":          ",".join(sorted(rule.actions)),
                    "source_ip":       self._networks_to_str(rule.source_networks),
                    "destination_ip":  self._networks_to_str(rule.destination_networks),
                    "note":            rule.note,
                    "status":          rule.status,
                    "ttl_days":        rule.expiry.ttl_days,
                    "last_hit_time":   la.isoformat() if la else "",
                    "hit_count":       rule.hit_count,
                })
        os.replace(tmp_path, self._csv_path)
        logger.debug(f"Whitelist written back: {len(snapshot)} rules → {self._csv_path}")

    async def reload(self) -> None:
        """Hot-reload rules from CSV (call after manual CSV edit)."""
        async with self._lock:
            self._load(self._csv_path)

    def suggest_rule(
        self,
        sig_id: str,
        sig_name: str,
        action: str,
        src_ip: str = "",
        dst_ip: str = "",
        note: str = "",
        ttl_days: int | None = None,
        status: str = "monitoring",
    ) -> str:
        """Register a pending whitelist rule and return a one-time approval token."""
        # Extract numeric ID from "Name(ID)" format if needed
        sig_id = self._extract_sig_id(sig_id) if sig_id else sig_id
        token = str(uuid.uuid4())
        self._pending_rules[token] = {
            "sig_id": sig_id,
            "sig_name": sig_name,
            "action": action,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "note": note or f"由 Email 核准：{date.today()}",
            "ttl_days": ttl_days,
            "status": status,
            "suggested_at": datetime.now(timezone.utc).isoformat(),
        }
        return token

    async def remove_rule(self, signature_id: str, src_ip: str = "", dst_ip: str = "") -> bool:
        """Remove a specific rule by compound key (sig_id + src_ip + dst_ip).
        When src_ip/dst_ip are omitted, falls back to removing all rules with that sig_id."""
        async with self._lock:
            before = len(self._rules)
            if src_ip or dst_ip:
                target_src = self._networks_to_str(self._parse_networks(src_ip))
                target_dst = self._networks_to_str(self._parse_networks(dst_ip))
                self._rules = [
                    r for r in self._rules
                    if not (
                        r.signature_id == signature_id
                        and self._networks_to_str(r.source_networks) == target_src
                        and self._networks_to_str(r.destination_networks) == target_dst
                    )
                ]
            else:
                self._rules = [r for r in self._rules if r.signature_id != signature_id]
            if len(self._rules) == before:
                return False
        await self.write_back()
        logger.info(f"Whitelist rule removed: {signature_id} src={src_ip!r} dst={dst_ip!r}")
        return True

    async def approve_rule(self, token: str) -> tuple[bool, str]:
        """Consume approval token and add rule in-memory + atomic CSV write-back."""
        rule_data = self._pending_rules.pop(token, None)
        if not rule_data:
            return False, "Token 不存在或已過期"
        ttl = rule_data.get("ttl_days")
        ttl_days = ttl if isinstance(ttl, int) else self._default_ttl_days
        new_rule = FPRule(
            signature_id=rule_data["sig_id"],
            signature_name=rule_data["sig_name"],
            actions={rule_data["action"]} if rule_data["action"] else set(),
            source_networks=self._parse_networks(rule_data["src_ip"]),
            destination_networks=self._parse_networks(rule_data["dst_ip"]),
            note=rule_data["note"],
            status=rule_data.get("status", "monitoring"),
            expiry=ExpiryPolicy(ttl_days=ttl_days, last_activity=None),
            hit_count=0,
        )
        async with self._lock:
            self._rules.append(new_rule)
            self._rules = self._dedup_rules(self._rules)
        await self.write_back()
        logger.info(f"Whitelist rule approved: {rule_data['sig_name']}")
        return True, f"白名單規則已新增：{rule_data['sig_name']}"

    # ------------------------------------------------------------------
    # Background sweeper
    # ------------------------------------------------------------------

    async def _sweeper_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self._sweep_interval)
                await self.sweep()
                await self.write_back()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Whitelist sweeper error: {e}", exc_info=True)

    async def start_sweeper(self) -> None:
        self._sweeper_task = asyncio.create_task(self._sweeper_loop())
        logger.info(f"Whitelist sweeper started (interval={self._sweep_interval}s)")

    async def stop_sweeper(self) -> None:
        if self._sweeper_task:
            self._sweeper_task.cancel()
            try:
                await self._sweeper_task
            except asyncio.CancelledError:
                pass
            await self.write_back()
            logger.info("Whitelist sweeper stopped, final write-back done")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _net_to_str(net: Any) -> str:
        if isinstance(net, str):
            return net
        # Return plain IP for host addresses (/32 or /128), CIDR otherwise
        if net.prefixlen == (32 if net.version == 4 else 128):
            return str(net.network_address)
        return str(net)

    @classmethod
    def _networks_to_str(cls, networks: list) -> str:
        return ",".join(cls._net_to_str(n) for n in networks)
