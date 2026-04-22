"""
Known False Positive Checker

從 known_fp.csv 載入已知誤判規則，在 triage 前快速過濾。
CSV 欄位：signature_id, signature_name, action, source_ip, destination_ip, rcvss, note
source_ip / destination_ip 支援單一 IP、逗號分隔多值、或 CIDR 網段（如 192.168.2.0/24）
"""

import csv
import ipaddress
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class KnownFPChecker:
    def __init__(self, csv_path: str):
        self._rules: list[dict] = []
        self._load(csv_path)

    def _load(self, csv_path: str):
        path = Path(csv_path)
        if not path.exists():
            logger.warning(f"known_fp CSV not found: {csv_path}")
            return
        with open(path, "r", encoding="utf-8") as f:
            lines = [line for line in f if not line.startswith("#")]
        reader = csv.DictReader(lines)
        for row in reader:
            actions = {a.strip() for a in row.get("action", "").split(",") if a.strip()}
            self._rules.append({
                "signature_id":        row.get("signature_id", "").strip(),
                "signature_name":      row.get("signature_name", "").strip(),
                "actions":             actions,
                "source_networks":     self._parse_networks(row.get("source_ip", "")),
                "destination_networks": self._parse_networks(row.get("destination_ip", "")),
                "note":                row.get("note", "").strip(),
            })
        logger.info(f"Loaded {len(self._rules)} known_fp rules from {csv_path}")

    @staticmethod
    def _parse_networks(raw: str) -> list:
        """將逗號分隔的 IP / CIDR 解析為 ip_network 清單；空白或 any = 萬用（空清單）。"""
        networks = []
        for item in raw.split(","):
            item = item.strip()
            if not item or item.lower() == "any":
                continue
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                logger.warning(f"known_fp: invalid IP/CIDR '{item}', skipping")
        return networks

    @staticmethod
    def _ip_in_networks(ip_str: str, networks: list) -> bool:
        """networks 為空（萬用）→ True；否則檢查 ip_str 是否落在任一 network 內。"""
        if not networks:
            return True
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(addr in net for net in networks)

    def check(self, summary: dict) -> str | None:
        """
        事件摘要與 known_fp 規則比對。
        命中時回傳規則 note 字串；未命中回傳 None。
        """
        sig_id = self._extract_id(
            summary.get("signature_id", "") or summary.get("signature_name", "")
        )
        action = summary.get("action", "")
        src_ip = summary.get("source_ip", "")
        dst_ip = summary.get("destination_ip", "")

        for rule in self._rules:
            if rule["signature_id"] != sig_id:
                continue
            if rule["actions"] and action not in rule["actions"]:
                continue
            if not self._ip_in_networks(src_ip, rule["source_networks"]):
                continue
            if not self._ip_in_networks(dst_ip, rule["destination_networks"]):
                continue
            note = rule["note"] or rule["signature_name"]
            logger.debug(f"known_fp match: sig={sig_id} src={src_ip} dst={dst_ip} → {note}")
            return note

        return None

    @staticmethod
    def _extract_id(signature: str) -> str:
        """從 'Microsoft Windows NTLMSSP Detection(92322)' 提取 '92322'"""
        if "(" in signature and signature.endswith(")"):
            return signature.rsplit("(", 1)[-1].rstrip(")")
        return signature
