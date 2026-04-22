"""
Email Notifier

負責將研判結果以結構化 email 寄送給分析人員。
"""

import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import aiosmtplib

logger = logging.getLogger(__name__)


class EmailNotifier:
    def __init__(self, config: dict):
        smtp_cfg = config.get("smtp", {})
        self.host = smtp_cfg.get("host", "localhost")
        self.port = smtp_cfg.get("port", 25)
        self.username = smtp_cfg.get("username", "")
        self.password = smtp_cfg.get("password", "")
        self.use_tls = smtp_cfg.get("use_tls", False)
        self.sender = smtp_cfg.get("sender", "graylog-analyzer@localhost")
        self.recipients = smtp_cfg.get("recipients", [])

    async def send_alert(
        self,
        subject: str,
        enriched_context: dict,
        verdict,
        edl_approve_url: str | None = None,
    ) -> bool:
        """寄送告警 email"""
        if not self.recipients:
            logger.warning("No email recipients configured, skipping notification.")
            return False

        body = self._format_email_body(enriched_context, verdict, edl_approve_url)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg.attach(MIMEText(body, "html", "utf-8"))

        try:
            await aiosmtplib.send(
                msg,
                hostname=self.host,
                port=self.port,
                username=self.username or None,
                password=self.password or None,
                use_tls=self.use_tls,
                start_tls=False,
                recipients=self.recipients,
            )
            logger.info(f"Alert email sent: {subject}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {e}", exc_info=True)
            return False

    def _format_email_body(
        self, enriched: dict, verdict, edl_approve_url: str | None = None
    ) -> str:
        """產生 HTML email 內容"""
        summary = enriched.get("event_summary", {})
        asset = enriched.get("asset_context", {})
        freq = enriched.get("frequency_context", {})
        src = asset.get("source_asset", {})
        dst = asset.get("destination_asset", {})

        verdict_color = {
            "anomalous": "#e74c3c",
            "false_positive": "#f39c12",
            "normal": "#27ae60",
        }.get(verdict.verdict, "#95a5a6")

        # EDL 封鎖建議區塊
        if verdict.edl_entry and edl_approve_url:
            edl_section = f"""
                <div style="margin: 16px 0; padding: 14px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 6px;">
                    <p style="margin: 0 0 8px 0;"><strong>建議封鎖：</strong> <code style="background:#f8f9fa; padding:2px 6px; border-radius:3px;">{verdict.edl_entry}</code></p>
                    <a href="{edl_approve_url}"
                       style="display:inline-block; padding:8px 18px; background:#dc3545; color:white; text-decoration:none; border-radius:4px; font-weight:bold;">
                        &#10003; 確認加入 EDL 封鎖清單
                    </a>
                    <p style="margin: 8px 0 0 0; color: #856404; font-size: 12px;">點擊上方按鈕後將立即寫入 EDL。此操作不可撤銷，請確認後再按。</p>
                </div>"""
        elif verdict.edl_entry:
            edl_section = f"""
                <p><strong>建議阻擋：</strong> <code>{verdict.edl_entry}</code>（尚待確認）</p>"""
        else:
            edl_section = ""

        return f"""
        <html>
        <body style="font-family: 'Segoe UI', sans-serif; max-width: 700px; margin: 0 auto;">
            <div style="background: {verdict_color}; color: white; padding: 16px; border-radius: 8px 8px 0 0;">
                <h2 style="margin: 0;">Verdict: {verdict.verdict.upper()}</h2>
                <p style="margin: 4px 0 0 0;">Confidence: {verdict.confidence} | Action: {verdict.recommended_action}</p>
            </div>

            <div style="border: 1px solid #ddd; border-top: none; padding: 16px; border-radius: 0 0 8px 8px;">
                <h3>AI 研判說明</h3>
                <p style="background: #f8f9fa; padding: 12px; border-radius: 4px; border-left: 4px solid {verdict_color};">
                    {verdict.reasoning}
                </p>

                {edl_section}

                <h3>事件摘要</h3>
                <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                    <tr><td style="padding: 6px; border-bottom: 1px solid #eee; font-weight: bold; width: 30%;">Signature</td>
                        <td style="padding: 6px; border-bottom: 1px solid #eee;">{summary.get('signature_name', '')}</td></tr>
                    <tr><td style="padding: 6px; border-bottom: 1px solid #eee; font-weight: bold;">Severity / Action</td>
                        <td style="padding: 6px; border-bottom: 1px solid #eee;">{summary.get('severity', '')} / {summary.get('action', '')}</td></tr>
                    <tr><td style="padding: 6px; border-bottom: 1px solid #eee; font-weight: bold;">來源</td>
                        <td style="padding: 6px; border-bottom: 1px solid #eee;">{summary.get('source_ip', '')} ({src.get('hostname', '?')}) — {summary.get('source_user', 'N/A')}</td></tr>
                    <tr><td style="padding: 6px; border-bottom: 1px solid #eee; font-weight: bold;">目標</td>
                        <td style="padding: 6px; border-bottom: 1px solid #eee;">{summary.get('destination_ip', '')} ({dst.get('hostname', '?')}) — {summary.get('destination_user', 'N/A')}</td></tr>
                    <tr><td style="padding: 6px; border-bottom: 1px solid #eee; font-weight: bold;">Zone 流向</td>
                        <td style="padding: 6px; border-bottom: 1px solid #eee;">{summary.get('zone_flow', '')}</td></tr>
                    <tr><td style="padding: 6px; border-bottom: 1px solid #eee; font-weight: bold;">防火牆規則</td>
                        <td style="padding: 6px; border-bottom: 1px solid #eee;">{summary.get('rule_name', '')}</td></tr>
                    <tr><td style="padding: 6px; border-bottom: 1px solid #eee; font-weight: bold;">RCVSS</td>
                        <td style="padding: 6px; border-bottom: 1px solid #eee;">{summary.get('rcvss', '')}</td></tr>
                </table>

                <h3>頻率上下文 (過去 24h)</h3>
                <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                    <tr><td style="padding: 6px; border-bottom: 1px solid #eee; font-weight: bold; width: 60%;">同來源 + 同 Signature</td>
                        <td style="padding: 6px; border-bottom: 1px solid #eee;">{freq.get('same_src_same_sig_24h', 'N/A')} 次</td></tr>
                    <tr><td style="padding: 6px; border-bottom: 1px solid #eee; font-weight: bold;">同來源 + 其他 Signature</td>
                        <td style="padding: 6px; border-bottom: 1px solid #eee;">{freq.get('same_src_other_sig_24h', 'N/A')} 次</td></tr>
                    <tr><td style="padding: 6px; border-bottom: 1px solid #eee; font-weight: bold;">同目標 + 同 Signature</td>
                        <td style="padding: 6px; border-bottom: 1px solid #eee;">{freq.get('same_dst_same_sig_24h', 'N/A')} 次</td></tr>
                </table>

                <p style="color: #999; font-size: 12px; margin-top: 20px;">
                    此郵件由 Graylog Threat Analyzer 自動產生。
                </p>
            </div>
        </body>
        </html>
        """
