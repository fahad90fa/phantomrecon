from __future__ import annotations

import asyncio
import hashlib
from typing import Optional
from urllib.parse import urlparse

from ..http_client import HttpClient
from ..models import Finding, ScanConfig, ScanModule, Severity

COMMON_VHOSTS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
    "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs",
    "ww42", "mx", "email", "cloud", "1", "mail1", "2", "forum", "owa",
    "www2", "gw", "admin", "store", "relay", "beta", "wiki",
    "api", "staging", "app", "crm", "erp", "git", "gitlab", "jenkins",
    "ci", "monitor", "prometheus", "grafana", "elk", "kibana",
    "jira", "confluence", "redmine", "svn", "dev2", "preprod",
    "uat", "qa", "internal", "intranet", "corp", "vpn2",
    "old", "new", "backup", "archive", "static", "assets", "cdn",
    "media", "images", "img", "upload", "download", "files",
    "api2", "v2", "rest", "ws", "socket", "push",
    "dashboard", "analytics", "metrics", "status", "health",
    "docs", "doc", "documentation", "help", "kb", "knowledge",
    "billing", "pay", "payment", "account", "accounts",
    "auth", "login", "oauth", "sso", "id", "identity",
    "smtp2", "pop3", "imap", "exchange", "autodiscover",
    "mx1", "mx2", "relay1", "relay2",
    "lb", "haproxy", "nginx", "proxy",
    "dev1", "dev3", "staging2", "pre", "demo",
]


class VHostScanner:
    def __init__(self, config: ScanConfig, client: HttpClient) -> None:
        self.config = config
        self.client = client

    async def scan(self, base_url: str, wordlist: Optional[list[str]] = None) -> list[Finding]:
        findings: list[Finding] = []

        parsed = urlparse(base_url)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme
        port = parsed.port

        parts = hostname.split(".")
        if len(parts) < 2:
            return findings

        base_domain = ".".join(parts[-2:])

        baseline_hash = await self._get_baseline(base_url, hostname)
        if not baseline_hash:
            return findings

        candidates = wordlist or COMMON_VHOSTS
        vhosts_to_check = [f"{sub}.{base_domain}" for sub in candidates]
        vhosts_to_check = [v for v in vhosts_to_check if v != hostname]

        found_vhosts: list[str] = []
        semaphore = asyncio.Semaphore(min(self.config.threads, 30))

        async def check_vhost(vhost: str) -> Optional[str]:
            async with semaphore:
                port_str = f":{port}" if port else ""
                url = f"{scheme}://{hostname}{port_str}/"
                host_header = f"{vhost}{port_str}" if port else vhost
                try:
                    resp = await self.client.get(
                        url,
                        extra_headers={"Host": host_header},
                        retries=1,
                    )
                    if resp and resp.status_code not in (400, 404, 000):
                        body_hash = hashlib.md5(resp.body[:1024].encode("utf-8", errors="replace")).hexdigest()
                        if body_hash != baseline_hash and resp.status_code in (200, 301, 302, 401, 403):
                            return vhost
                except Exception:
                    pass
                return None

        results = await asyncio.gather(*[check_vhost(v) for v in vhosts_to_check], return_exceptions=True)

        for r in results:
            if isinstance(r, str):
                found_vhosts.append(r)

        for vhost in found_vhosts:
            findings.append(Finding(
                url=f"{scheme}://{vhost}/",
                title=f"Virtual Host Discovered: {vhost}",
                severity=Severity.MEDIUM,
                module=ScanModule.VULNS,
                description=f"Virtual host '{vhost}' responds differently from the baseline, indicating it may be a valid vhost.",
                evidence=f"Host header '{vhost}' returned a different response than baseline.",
                recommendation="Ensure discovered virtual hosts are intentional and properly secured.",
            ))

        if found_vhosts:
            findings.insert(0, Finding(
                url=base_url,
                title=f"Virtual Hosts Discovered ({len(found_vhosts)})",
                severity=Severity.INFO,
                module=ScanModule.VULNS,
                description=f"Found {len(found_vhosts)} virtual host(s): {', '.join(found_vhosts[:10])}",
                evidence=f"Hosts: {', '.join(found_vhosts)}",
                recommendation="Review each discovered vhost for proper access controls.",
            ))

        return findings

    async def _get_baseline(self, base_url: str, hostname: str) -> Optional[str]:
        try:
            resp = await self.client.get(base_url, extra_headers={"Host": hostname}, retries=2)
            if resp:
                return hashlib.md5(resp.body[:1024].encode("utf-8", errors="replace")).hexdigest()
        except Exception:
            pass
        return None
