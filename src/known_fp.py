"""
Known False Positive Checker

從 known_fp.csv 載入已知誤判規則，在 triage 前快速過濾。
CSV 欄位：signature_id, signature_name, action, source_ip, destination_ip, rcvss, note
"""

import csv
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
            source_ips = {ip.strip() for ip in row.get("source_ip", "").split(",") if ip.strip()}
            dst_raw = row.get("destination_ip", "").strip()
            if dst_raw.lower() in ("", "any"):
                destination_ips: set[str] = set()
            else:
                destination_ips = {ip.strip() for ip in dst_raw.split(",") if ip.strip()}

            self._rules.append({
                "signature_id":   row.get("signature_id", "").strip(),
                "signature_name": row.get("signature_name", "").strip(),
                "actions":        actions,
                "source_ips":     source_ips,
                "destination_ips": destination_ips,
                "note":           row.get("note", "").strip(),
            })
        logger.info(f"Loaded {len(self._rules)} known_fp rules from {csv_path}")

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
            if rule["source_ips"] and src_ip not in rule["source_ips"]:
                continue
            if rule["destination_ips"] and dst_ip not in rule["destination_ips"]:
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
