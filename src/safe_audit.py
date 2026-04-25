"""
Safe Audit

將每個研判結果以 JSONL 格式寫入每日稽核檔。
儲存位置：{output_dir}/{YYYY-MM-DD}.jsonl
每行一個 JSON 物件，欄位：timestamp / stage / verdict / event_summary
"""

import asyncio
import csv
import io
import json
import logging
from datetime import date, datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class SafeAudit:
    def __init__(self, output_dir: str):
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    async def record(self, enriched: dict, verdict, stage: str) -> None:
        """
        Append one triage result to today's JSONL file.
        stage: "rate_limit" | "whitelist" | "gate3_rule" | "gate3_llm"
        """
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "verdict": verdict.model_dump(),
            "event_summary": enriched.get("event_summary", {}),
        }
        line = json.dumps(payload, ensure_ascii=False)
        path = self._today_path()
        async with self._lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def _today_path(self) -> Path:
        return self._output_dir / f"{date.today()}.jsonl"

    def export_jsonl(self, date_str: str) -> Path | None:
        """Return Path to JSONL file for given date, or None if not found."""
        path = self._output_dir / f"{date_str}.jsonl"
        return path if path.exists() else None

    def export_csv(self, date_str: str) -> str | None:
        """
        Convert JSONL to CSV string for analyst consumption.
        Columns: timestamp, stage, verdict, confidence, reasoning,
                 recommended_action, src_ip, dst_ip, signature_id, signature_name
        Returns None if no file for that date.
        """
        path = self.export_jsonl(date_str)
        if path is None:
            return None

        columns = [
            "timestamp", "stage", "verdict", "confidence", "reasoning",
            "recommended_action", "src_ip", "dst_ip", "signature_id", "signature_name",
        ]
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                v = rec.get("verdict", {})
                es = rec.get("event_summary", {})
                writer.writerow({
                    "timestamp":          rec.get("timestamp", ""),
                    "stage":              rec.get("stage", ""),
                    "verdict":            v.get("verdict", ""),
                    "confidence":         v.get("confidence", ""),
                    "reasoning":          v.get("reasoning", ""),
                    "recommended_action": v.get("recommended_action", ""),
                    "src_ip":             es.get("source_ip", ""),
                    "dst_ip":             es.get("destination_ip", ""),
                    "signature_id":       es.get("signature_id", "") or es.get("threat_id", ""),
                    "signature_name":     es.get("signature_name", "") or es.get("alert_signature", ""),
                })

        return output.getvalue()
