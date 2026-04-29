"""
Email Notifier

負責將研判結果以結構化 email 寄送給分析人員。
"""

import logging
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib

logger = logging.getLogger(__name__)

# Brand colors (inline; email clients strip <style>)
_NAVY    = "#1B3A6B"
_BLUE    = "#2E74B5"
_LIGHT   = "#BDD7EE"
_PALE    = "#DEEAF1"
_GRAY    = "#595959"
_BG      = "#F0F4FA"
_WHITE   = "#FFFFFF"
_RED     = "#C00000"
_ORANGE  = "#ED7D31"
_GREEN   = "#375623"
_AMBER   = "#856404"
_AMBER_BG = "#FFF8E1"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


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
        whitelist_approve_url: str | None = None,
    ) -> bool:
        """寄送告警 email"""
        if not self.recipients:
            logger.warning("No email recipients configured, skipping notification.")
            return False

        body = self._format_email_body(enriched_context, verdict, edl_approve_url, whitelist_approve_url)

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
        self,
        enriched: dict,
        verdict,
        edl_approve_url: str | None = None,
        whitelist_approve_url: str | None = None,
    ) -> str:
        """產生 HTML email 內容（專業藍色主題）"""
        summary = enriched.get("event_summary", {})
        asset   = enriched.get("asset_context", {})
        freq    = enriched.get("frequency_context", {})
        src     = asset.get("source_asset", {})
        dst     = asset.get("destination_asset", {})

        verdict_color = {
            "anomalous":     _RED,
            "false_positive": _BLUE,
            "normal":        _GREEN,
        }.get(verdict.verdict, _GRAY)

        verdict_label = verdict.verdict.upper()
        action_upper  = verdict.recommended_action.upper()

        both_actions = bool(edl_approve_url and whitelist_approve_url)

        # ── Action cards ──────────────────────────────────────────────────────

        if both_actions:
            dual_hint = f"""
            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:16px">
              <tr>
                <td style="background:{_AMBER_BG};border:1px solid #FFD54F;border-left:4px solid {_ORANGE};
                           border-radius:6px;padding:12px 16px;font-family:Arial,sans-serif;
                           font-size:13px;color:{_AMBER};">
                  ⚠️ <strong>請依調查結果擇一操作</strong>：確認惡意請按封鎖；確認誤判請按加入白名單。
                </td>
              </tr>
            </table>"""
        else:
            dual_hint = ""

        if edl_approve_url and verdict.edl_entry:
            edl_card = f"""
            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:16px">
              <tr>
                <td style="background:#FFF5F5;border:1px solid #FFCDD2;border-left:4px solid {_RED};
                           border-radius:6px;padding:16px 20px;font-family:Arial,sans-serif;">
                  <p style="margin:0 0 6px 0;font-size:13px;font-weight:700;color:{_RED};">
                    🔴 建議加入 EDL 封鎖清單
                  </p>
                  <p style="margin:0 0 14px 0;font-size:13px;color:{_GRAY};">
                    封鎖目標：<code style="background:#f5f5f5;padding:2px 6px;border-radius:3px;
                    font-family:Consolas,monospace;">{verdict.edl_entry}</code>
                  </p>
                  <a href="{edl_approve_url}"
                     style="display:inline-block;padding:10px 22px;background:{_RED};
                            color:#fff;text-decoration:none;border-radius:5px;
                            font-family:Arial,sans-serif;font-size:13px;font-weight:700;">
                    &#10003; 確認加入 EDL 封鎖清單
                  </a>
                  <p style="margin:10px 0 0 0;font-size:11px;color:{_GRAY};">
                    點擊後立即生效，PA 下次拉取時封鎖。如需撤銷請至 Dashboard 移除。
                  </p>
                </td>
              </tr>
            </table>"""
        elif verdict.edl_entry:
            edl_card = f"""
            <p style="font-family:Arial,sans-serif;font-size:13px;color:{_GRAY};margin:0 0 16px 0;">
              <strong>AI 建議封鎖：</strong>
              <code style="background:#f5f5f5;padding:2px 6px;border-radius:3px;
                    font-family:Consolas,monospace;">{verdict.edl_entry}</code>（需人工確認）
            </p>"""
        else:
            edl_card = ""

        if whitelist_approve_url:
            wl_label = "確認為誤判 — 加入白名單" if both_actions else "確認加入白名單"
            or_prefix = "<strong>或：</strong>" if both_actions else ""
            wl_card = f"""
            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:16px">
              <tr>
                <td style="background:#FFF8F0;border:1px solid #FFD0A0;border-left:4px solid {_ORANGE};
                           border-radius:6px;padding:16px 20px;font-family:Arial,sans-serif;">
                  <p style="margin:0 0 6px 0;font-size:13px;font-weight:700;color:#BF5000;">
                    📋 {or_prefix}確認為誤判？加入白名單
                  </p>
                  <p style="margin:0 0 14px 0;font-size:13px;color:{_GRAY};">
                    加入後此 Signature 將以 <em>monitoring</em> 狀態追蹤，不再產生告警。
                  </p>
                  <a href="{whitelist_approve_url}"
                     style="display:inline-block;padding:10px 22px;background:{_ORANGE};
                            color:#fff;text-decoration:none;border-radius:5px;
                            font-family:Arial,sans-serif;font-size:13px;font-weight:700;">
                    &#10003; {wl_label}
                  </a>
                  <p style="margin:10px 0 0 0;font-size:11px;color:{_GRAY};">
                    TTL {90} 天，到期後自動失效。如需提前移除請至 Dashboard 操作。
                  </p>
                </td>
              </tr>
            </table>"""
        else:
            wl_card = ""

        # ── Event info rows ───────────────────────────────────────────────────

        def _row(label: str, value: str, alt: bool = False) -> str:
            bg = "#F8F9FA" if alt else _WHITE
            return (
                f'<tr style="background:{bg}">'
                f'<td style="padding:8px 14px;font-family:Arial,sans-serif;font-size:13px;'
                f'font-weight:700;color:{_GRAY};width:36%;border-bottom:1px solid #EEF2F8;">'
                f'{label}</td>'
                f'<td style="padding:8px 14px;font-family:Arial,sans-serif;font-size:13px;'
                f'color:#1A1A2E;border-bottom:1px solid #EEF2F8;">{value}</td>'
                f'</tr>'
            )

        sig_name   = summary.get("signature_name", "")
        sig_id     = summary.get("signature_id", "")
        sig_display = f"{sig_id} / {sig_name}" if sig_id and sig_name else (sig_name or sig_id or "—")
        src_ip     = summary.get("source_ip", "")
        src_host   = src.get("hostname", "")
        dst_ip     = summary.get("destination_ip", "")
        dst_host   = dst.get("hostname", "")
        src_label  = f"{src_ip} ({src_host})" if src_host else src_ip
        dst_label  = f"{dst_ip} ({dst_host})" if dst_host else dst_ip
        src_user   = summary.get("source_user", "") or "N/A"
        dst_user   = summary.get("destination_user", "") or "N/A"

        event_rows = "".join([
            _row("Signature",      sig_display),
            _row("Severity / Action", f"{summary.get('severity','')} / {summary.get('action','')}", True),
            _row("來源 IP",         f"{src_label} — {src_user}"),
            _row("目標 IP",         f"{dst_label} — {dst_user}", True),
            _row("Zone 流向",       summary.get("zone_flow", ""), False),
            _row("防火牆規則",      summary.get("rule_name", ""), True),
            _row("RCVSS",          summary.get("rcvss", ""), False),
        ])

        freq_rows = "".join([
            _row("同來源 + 同 Signature",   f"{freq.get('same_src_same_sig_24h','N/A')} 次"),
            _row("同來源 + 其他 Signature", f"{freq.get('same_src_other_sig_24h','N/A')} 次", True),
            _row("同目標 + 同 Signature",   f"{freq.get('same_dst_same_sig_24h','N/A')} 次"),
        ])

        return f"""<!DOCTYPE html>
<html lang="zh-TW">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:{_BG};font-family:Arial,'Segoe UI',sans-serif;">

<table width="100%" cellpadding="0" cellspacing="0" style="background:{_BG};padding:24px 0">
<tr><td align="center">
<table width="680" cellpadding="0" cellspacing="0"
       style="max-width:680px;background:{_WHITE};border-radius:8px;
              box-shadow:0 2px 12px rgba(27,58,107,.15);overflow:hidden">

  <!-- HEADER -->
  <tr>
    <td style="background:{_NAVY};padding:20px 28px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td>
            <p style="margin:0;font-size:18px;font-weight:700;color:{_WHITE};letter-spacing:.3px;">
              Graylog Threat Analyzer
            </p>
            <p style="margin:3px 0 0;font-size:12px;color:{_LIGHT};letter-spacing:.5px;">
              SECURITY OPERATIONS CENTER
            </p>
          </td>
          <td align="right" style="vertical-align:top;">
            <p style="margin:0;font-size:11px;color:rgba(255,255,255,.6);">{_ts()}</p>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- VERDICT BANNER -->
  <tr>
    <td style="padding:0 28px;">
      <table width="100%" cellpadding="0" cellspacing="0" style="margin:20px 0 0">
        <tr>
          <td style="background:#F8F9FA;border-left:5px solid {verdict_color};
                     border-radius:0 6px 6px 0;padding:14px 18px;">
            <p style="margin:0;font-size:20px;font-weight:700;color:{verdict_color};
                      letter-spacing:.5px;">{verdict_label}</p>
            <p style="margin:4px 0 0;font-size:13px;color:{_GRAY};">
              Confidence: <strong>{verdict.confidence.upper()}</strong>
              &nbsp;|&nbsp;
              Action: <strong>{action_upper}</strong>
            </p>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- AI REASONING -->
  <tr>
    <td style="padding:20px 28px 0">
      <p style="margin:0 0 8px;font-size:14px;font-weight:700;color:{_NAVY};">AI 研判說明</p>
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="background:#F8F9FA;border-left:4px solid {verdict_color};
                     border-radius:0 6px 6px 0;padding:12px 16px;">
            <p style="margin:0;font-size:13px;color:#1A1A2E;line-height:1.6;">
              {verdict.reasoning}
            </p>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- ACTION CARDS -->
  <tr>
    <td style="padding:20px 28px 0">
      {dual_hint}{edl_card}{wl_card}
    </td>
  </tr>

  <!-- DIVIDER -->
  <tr>
    <td style="padding:4px 28px 0">
      <hr style="border:none;border-top:1px solid #E8EEF6;margin:0">
    </td>
  </tr>

  <!-- EVENT SUMMARY -->
  <tr>
    <td style="padding:20px 28px 0">
      <p style="margin:0 0 10px;font-size:14px;font-weight:700;color:{_NAVY};">事件摘要</p>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border:1px solid #E8EEF6;border-radius:6px;overflow:hidden;">
        {event_rows}
      </table>
    </td>
  </tr>

  <!-- FREQUENCY CONTEXT -->
  <tr>
    <td style="padding:20px 28px 0">
      <p style="margin:0 0 10px;font-size:14px;font-weight:700;color:{_NAVY};">
        過去 24h 頻率分析
      </p>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border:1px solid #E8EEF6;border-radius:6px;overflow:hidden;">
        {freq_rows}
      </table>
    </td>
  </tr>

  <!-- FOOTER -->
  <tr>
    <td style="padding:24px 28px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="background:{_PALE};border-radius:6px;padding:14px 18px;">
            <p style="margin:0;font-size:12px;color:{_GRAY};">
              此郵件由 <strong>Graylog Threat Analyzer</strong> 自動產生，請勿直接回覆。
              如有問題，請聯絡 SOC 團隊。
            </p>
          </td>
        </tr>
      </table>
    </td>
  </tr>

</table>
</td></tr>
</table>

</body>
</html>"""
