from __future__ import annotations

from typing import Any

from ..models import Finding, ScanModule, Severity
from .base_plugin import BasePlugin


class RobotsAnalyzerPlugin(BasePlugin):
    name = "robots_analyzer"
    version = "1.0.0"
    description = "Analyzes robots.txt for hidden paths and disallowed entries"
    author = "PhantomRecon"

    async def run(self, target: str, **kwargs: Any) -> list[Finding]:
        if not self.client:
            return []

        findings: list[Finding] = []
        base = target.rstrip("/")
        url = f"{base}/robots.txt"

        resp = await self.client.get(url, retries=1)
        if not resp or resp.status_code != 200:
            return findings

        disallowed: list[str] = []
        allowed: list[str] = []
        sitemaps: list[str] = []

        for line in resp.body.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line[9:].strip()
                if path and path != "/":
                    disallowed.append(path)
            elif line.lower().startswith("allow:"):
                path = line[6:].strip()
                if path:
                    allowed.append(path)
            elif line.lower().startswith("sitemap:"):
                sitemap = line[8:].strip()
                if sitemap:
                    sitemaps.append(sitemap)

        if disallowed:
            sensitive_paths = [p for p in disallowed if any(
                kw in p.lower() for kw in ["admin", "config", "backup", "api", "private", "secret", "internal"]
            )]

            findings.append(Finding(
                url=url,
                title=f"robots.txt Disallows {len(disallowed)} Path(s)",
                severity=Severity.INFO,
                module=ScanModule.VULNS,
                description=f"robots.txt reveals {len(disallowed)} disallowed path(s) which may indicate hidden functionality.",
                evidence=f"Disallowed paths: {', '.join(disallowed[:20])}",
                recommendation="Note that robots.txt is public and disallowed paths are visible to all crawlers.",
            ))

            if sensitive_paths:
                findings.append(Finding(
                    url=url,
                    title=f"Sensitive Paths in robots.txt ({len(sensitive_paths)})",
                    severity=Severity.MEDIUM,
                    module=ScanModule.VULNS,
                    description="robots.txt reveals potentially sensitive paths that should be investigated.",
                    evidence=f"Sensitive paths: {', '.join(sensitive_paths[:10])}",
                    recommendation="Ensure these paths are properly protected with authentication and access controls.",
                ))

        if sitemaps:
            findings.append(Finding(
                url=url,
                title=f"Sitemaps Listed in robots.txt ({len(sitemaps)})",
                severity=Severity.INFO,
                module=ScanModule.VULNS,
                description=f"robots.txt references {len(sitemaps)} sitemap(s).",
                evidence=f"Sitemaps: {', '.join(sitemaps)}",
                recommendation="Review sitemaps for unintended path exposure.",
            ))

        return findings
