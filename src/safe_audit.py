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

    def aggregate(self, start_date: str, end_date: str) -> dict:
        """
        Aggregate audit records across a date range (inclusive).
        Returns structured stats dict consumed by /report/summary and report_generator.
        """
        from collections import Counter, defaultdict
        from datetime import date as date_type, timedelta

        start = date_type.fromisoformat(start_date)
        end = date_type.fromisoformat(end_date)

        records: list[dict] = []
        current = start
        while current <= end:
            path = self._output_dir / f"{current}.jsonl"
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            current += timedelta(days=1)

        return self._compute_stats(records, start_date, end_date)

    def _compute_stats(self, records: list[dict], start_date: str, end_date: str) -> dict:
        from collections import Counter, defaultdict

        total = len(records)
        action_counts: Counter = Counter()
        verdict_counts: Counter = Counter()
        signature_counts: Counter = Counter()
        daily_counts: dict = defaultdict(int)
        block_events: list[dict] = []
        pending_events: list[dict] = []

        for rec in records:
            v = rec.get("verdict", {})
            es = rec.get("event_summary", {})
            action = v.get("recommended_action", "suppress")
            verdict = v.get("verdict", "unknown")

            action_counts[action] += 1
            verdict_counts[verdict] += 1

            sig = es.get("signature_name") or es.get("signature_id", "—")
            signature_counts[sig] += 1

            ts = rec.get("timestamp", "")
            if ts:
                daily_counts[ts[:10]] += 1

            event_row = {
                "timestamp": ts[:19].replace("T", " ") if ts else "",
                "src_ip": es.get("source_ip", ""),
                "dst_ip": es.get("destination_ip", ""),
                "signature": sig,
                "action": action,
                "reasoning": v.get("reasoning", ""),
            }
            if action == "block":
                block_events.append(event_row)
            elif action in ("monitor", "investigate"):
                pending_events.append(event_row)

        suppressed = action_counts.get("suppress", 0)
        suppression_rate = round(suppressed / total * 100, 1) if total > 0 else 0.0

        return {
            "period": {"start": start_date, "end": end_date},
            "total_events": total,
            "suppression_rate": suppression_rate,
            "action_counts": dict(action_counts),
            "verdict_counts": dict(verdict_counts),
            "top_signatures": signature_counts.most_common(10),
            "daily_counts": dict(sorted(daily_counts.items())),
            "block_events": block_events[:50],
            "pending_events": pending_events[:50],
        }
