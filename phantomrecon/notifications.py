from __future__ import annotations

import json
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError


class NotificationManager:
    def __init__(
        self,
        slack_webhook: Optional[str] = None,
        discord_webhook: Optional[str] = None,
        email_cfg: Optional[dict] = None,
        notify_on: Optional[list[str]] = None,
    ) -> None:
        self.slack_webhook = slack_webhook
        self.discord_webhook = discord_webhook
        self.email_cfg = email_cfg or {}
        self.notify_on = notify_on or ["critical", "high"]

    def should_notify(self, severity: str) -> bool:
        return severity.lower() in self.notify_on

    def notify_finding(self, finding: dict, target: str) -> None:
        sev = finding.get("severity", "info")
        if not self.should_notify(sev):
            return
        msg = self._format_finding(finding, target)
        self._send_all(
            title=f"[PhantomRecon] {sev.upper()} Finding: {finding.get('title', '')}",
            body=msg,
            color=self._sev_color(sev),
        )

    def notify_scan_complete(self, result_summary: dict) -> None:
        target = result_summary.get("target", "unknown")
        findings = result_summary.get("total_findings", 0)
        critical = result_summary.get("critical", 0)
        high = result_summary.get("high", 0)
        body = (
            f"Scan complete for **{target}**\n"
            f"• Findings: {findings}  (Critical: {critical}, High: {high})\n"
            f"• Paths: {result_summary.get('paths', 0)}\n"
            f"• Requests: {result_summary.get('requests', 0)}\n"
            f"• Duration: {result_summary.get('duration', 0):.1f}s"
        )
        self._send_all(
            title=f"[PhantomRecon] Scan Complete — {target}",
            body=body,
            color="#00ff41",
        )

    def notify_custom(self, title: str, body: str) -> None:
        self._send_all(title=title, body=body, color="#4488ff")

    def _send_all(self, title: str, body: str, color: str = "#888") -> None:
        errors = []
        if self.slack_webhook:
            try:
                self._send_slack(title, body, color)
            except Exception as e:
                errors.append(f"Slack: {e}")
        if self.discord_webhook:
            try:
                self._send_discord(title, body, color)
            except Exception as e:
                errors.append(f"Discord: {e}")
        if self.email_cfg.get("smtp_host"):
            try:
                self._send_email(title, body)
            except Exception as e:
                errors.append(f"Email: {e}")

    def _send_slack(self, title: str, body: str, color: str) -> None:
        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": title,
                    "text": body,
                    "footer": "PhantomRecon",
                    "ts": __import__("time").time(),
                }
            ]
        }
        self._http_post(self.slack_webhook, payload)

    def _send_discord(self, title: str, body: str, color: str) -> None:
        hex_color = int(color.lstrip("#"), 16) if color.startswith("#") else 0x00ff41
        payload = {
            "embeds": [
                {
                    "title": title,
                    "description": body,
                    "color": hex_color,
                    "footer": {"text": "PhantomRecon"},
                }
            ]
        }
        self._http_post(self.discord_webhook, payload)

    def _send_email(self, subject: str, body: str) -> None:
        cfg = self.email_cfg
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = cfg.get("from_addr", "phantomrecon@localhost")
        msg["To"] = cfg.get("to_addr", "")

        html_body = f"""
        <html><body style='font-family:monospace;background:#0d0d0d;color:#e0e0e0;padding:20px'>
        <h2 style='color:#00ff41'>{subject}</h2>
        <pre style='color:#ccc'>{body}</pre>
        <hr style='border-color:#333'/>
        <small style='color:#555'>PhantomRecon — Authorized Penetration Testing Tool</small>
        </body></html>
        """
        msg.attach(MIMEText(body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        use_tls = cfg.get("use_tls", True)
        port = cfg.get("port", 587)
        host = cfg.get("smtp_host", "")

        if use_tls:
            ctx = ssl.create_default_context()
            with smtplib.SMTP(host, port) as server:
                server.ehlo()
                server.starttls(context=ctx)
                if cfg.get("username"):
                    server.login(cfg["username"], cfg.get("password", ""))
                server.sendmail(msg["From"], msg["To"], msg.as_string())
        else:
            with smtplib.SMTP(host, port) as server:
                if cfg.get("username"):
                    server.login(cfg["username"], cfg.get("password", ""))
                server.sendmail(msg["From"], msg["To"], msg.as_string())

    @staticmethod
    def _http_post(url: str, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        req = Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(req, timeout=10) as resp:
            resp.read()

    @staticmethod
    def _format_finding(finding: dict, target: str) -> str:
        return (
            f"Target: {target}\n"
            f"Title: {finding.get('title', '')}\n"
            f"Severity: {finding.get('severity', '').upper()}\n"
            f"URL: {finding.get('url', '')}\n"
            f"Module: {finding.get('module', '')}\n"
            f"CVE: {finding.get('cve') or 'N/A'}\n\n"
            f"{finding.get('description', '')}\n\n"
            f"Evidence: {finding.get('evidence', '')}"
        )

    @staticmethod
    def _sev_color(sev: str) -> str:
        return {
            "critical": "#ff0040",
            "high":     "#ff6600",
            "medium":   "#ffcc00",
            "low":      "#4488ff",
            "info":     "#888888",
        }.get(sev.lower(), "#888888")

    @classmethod
    def from_config(cls, cfg: dict) -> "NotificationManager":
        return cls(
            slack_webhook=cfg.get("slack_webhook"),
            discord_webhook=cfg.get("discord_webhook"),
            email_cfg=cfg.get("email", {}),
            notify_on=cfg.get("notify_on", ["critical", "high"]),
        )
