from __future__ import annotations

import asyncio
import json
import re
import socket
import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse
from urllib.request import urlopen, Request

import aiohttp


class SubdomainResult:
    def __init__(self, subdomain: str, ip: str, status: int = 0, banner: str = "") -> None:
        self.subdomain = subdomain
        self.ip = ip
        self.status = status
        self.banner = banner
        self.sources: list[str] = []
        self.timestamp = time.time()

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "ip": self.ip,
            "status": self.status,
            "banner": self.banner,
            "sources": self.sources,
        }


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "admin", "api", "app",
    "dev", "staging", "test", "beta", "prod", "production", "demo", "shop",
    "store", "blog", "forum", "portal", "cdn", "static", "media", "img",
    "assets", "upload", "files", "download", "secure", "ssl", "vpn", "remote",
    "ns1", "ns2", "mx", "mx1", "mx2", "webmail", "cpanel", "whm", "autodiscover",
    "autoconfig", "pop3", "imap4", "exchange", "owa", "mobile", "m", "wap",
    "gateway", "proxy", "firewall", "jenkins", "gitlab", "git", "svn", "jira",
    "confluence", "wiki", "kb", "helpdesk", "support", "status", "monitor",
    "grafana", "kibana", "elasticsearch", "db", "database", "mysql", "postgres",
    "redis", "mongo", "api2", "api3", "v1", "v2", "v3", "internal", "intranet",
    "extranet", "crm", "erp", "hr", "finance", "analytics", "data", "reporting",
    "auth", "sso", "login", "oauth", "id", "accounts", "pay", "payment",
    "checkout", "cart", "billing", "invoice", "backup", "staging2", "uat",
    "qa", "ci", "cd", "build", "deploy", "registry", "docker", "k8s",
    "kubernetes", "aws", "azure", "gcp", "cloud", "s3", "storage",
]


class SubdomainScanner:
    def __init__(
        self,
        domain: str,
        threads: int = 50,
        timeout: int = 5,
        wordlist: Optional[list[str]] = None,
        callback: Optional[Callable] = None,
        use_passive: bool = True,
        use_brute: bool = True,
    ) -> None:
        self.domain = self._extract_domain(domain)
        self.threads = threads
        self.timeout = timeout
        self.wordlist = wordlist or COMMON_SUBDOMAINS
        self.callback = callback
        self.use_passive = use_passive
        self.use_brute = use_brute
        self.results: dict[str, SubdomainResult] = {}
        self._sem = asyncio.Semaphore(threads)

    def _extract_domain(self, target: str) -> str:
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or ""
        else:
            host = target
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host

    async def scan(self) -> list[SubdomainResult]:
        tasks = []
        if self.use_passive:
            tasks.extend([
                self._passive_crtsh(),
                self._passive_dnsdumpster(),
                self._passive_threatcrowd(),
                self._passive_wayback(),
            ])

        await asyncio.gather(*tasks, return_exceptions=True)

        if self.use_brute:
            await self._brute_force()

        return list(self.results.values())

    async def _brute_force(self) -> None:
        sem = asyncio.Semaphore(self.threads)
        tasks = [self._check_subdomain(sub, sem) for sub in self.wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_subdomain(self, sub: str, sem: asyncio.Semaphore) -> None:
        fqdn = f"{sub}.{self.domain}"
        async with sem:
            try:
                loop = asyncio.get_event_loop()
                ips = await loop.run_in_executor(None, self._resolve, fqdn)
                if ips:
                    result = self._add_result(fqdn, ips[0], ["brute-force"])
                    await self._probe_http(result)
                    if self.callback:
                        self.callback(result)
            except Exception:
                pass

    async def _passive_crtsh(self) -> None:
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
            data = await asyncio.get_event_loop().run_in_executor(
                None, lambda: json.loads(urlopen(req, timeout=15).read())
            )
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.splitlines():
                    line = line.strip().lstrip("*.")
                    if line.endswith(self.domain) and line != self.domain:
                        subs.add(line)
            for sub in subs:
                try:
                    loop = asyncio.get_event_loop()
                    ips = await loop.run_in_executor(None, self._resolve, sub)
                    if ips:
                        result = self._add_result(sub, ips[0], ["crt.sh"])
                        await self._probe_http(result)
                        if self.callback:
                            self.callback(result)
                except Exception:
                    pass
        except Exception:
            pass

    async def _passive_dnsdumpster(self) -> None:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api.hackertarget.com/hostsearch/",
                    params={"q": self.domain},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    text = await resp.text()
                    for line in text.splitlines():
                        parts = line.split(",")
                        if len(parts) >= 2:
                            sub = parts[0].strip()
                            ip = parts[1].strip()
                            if sub.endswith(self.domain) and sub != self.domain:
                                result = self._add_result(sub, ip, ["hackertarget"])
                                if self.callback:
                                    self.callback(result)
        except Exception:
            pass

    async def _passive_threatcrowd(self) -> None:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://www.threatcrowd.org/searchApi/v2/domain/report/",
                    params={"domain": self.domain},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    data = await resp.json()
                    for sub in data.get("subdomains", []):
                        sub = sub.strip()
                        if sub.endswith(self.domain) and sub != self.domain:
                            try:
                                loop = asyncio.get_event_loop()
                                ips = await loop.run_in_executor(None, self._resolve, sub)
                                ip = ips[0] if ips else ""
                                result = self._add_result(sub, ip, ["threatcrowd"])
                                if self.callback:
                                    self.callback(result)
                            except Exception:
                                pass
        except Exception:
            pass

    async def _passive_wayback(self) -> None:
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=text&fl=original&collapse=urlkey&limit=500"
            req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
            text = await asyncio.get_event_loop().run_in_executor(
                None, lambda: urlopen(req, timeout=20).read().decode()
            )
            pattern = re.compile(rf"https?://([a-zA-Z0-9\-\.]+\.{re.escape(self.domain)})")
            found = set(pattern.findall(text))
            for sub in found:
                if sub != self.domain:
                    try:
                        loop = asyncio.get_event_loop()
                        ips = await loop.run_in_executor(None, self._resolve, sub)
                        ip = ips[0] if ips else ""
                        result = self._add_result(sub, ip, ["wayback"])
                        if self.callback:
                            self.callback(result)
                    except Exception:
                        pass
        except Exception:
            pass

    async def _probe_http(self, result: SubdomainResult) -> None:
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{result.subdomain}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=True,
                        ssl=False,
                    ) as resp:
                        result.status = resp.status
                        result.banner = resp.headers.get("Server", "")
                        return
            except Exception:
                continue

    def _add_result(self, subdomain: str, ip: str, sources: list[str]) -> SubdomainResult:
        if subdomain in self.results:
            for src in sources:
                if src not in self.results[subdomain].sources:
                    self.results[subdomain].sources.append(src)
            return self.results[subdomain]
        result = SubdomainResult(subdomain=subdomain, ip=ip)
        result.sources = sources
        self.results[subdomain] = result
        return result

    @staticmethod
    def _resolve(hostname: str) -> list[str]:
        try:
            info = socket.getaddrinfo(hostname, None)
            return list({i[4][0] for i in info})
        except Exception:
            return []


class DNSRecon:
    def __init__(self, domain: str, timeout: int = 5) -> None:
        self.domain = self._extract_domain(domain)
        self.timeout = timeout

    def _extract_domain(self, target: str) -> str:
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target
        return target

    async def full_recon(self) -> dict:
        results: dict[str, Any] = {
            "domain": self.domain,
            "a": [],
            "aaaa": [],
            "mx": [],
            "ns": [],
            "txt": [],
            "cname": [],
            "soa": [],
            "zone_transfer": [],
            "spf": None,
            "dmarc": None,
            "dkim_selectors": [],
            "wildcard": False,
            "dnssec": False,
        }

        try:
            import dns.resolver
            import dns.zone
            import dns.query

            resolver = dns.resolver.Resolver()
            resolver.lifetime = self.timeout

            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
                try:
                    answers = resolver.resolve(self.domain, rtype)
                    key = rtype.lower()
                    for rdata in answers:
                        results[key].append(str(rdata))
                except Exception:
                    pass

            for txt in results["txt"]:
                if txt.lower().startswith('"v=spf1') or txt.lower().startswith('v=spf1'):
                    results["spf"] = txt

            try:
                dmarc_answers = resolver.resolve(f"_dmarc.{self.domain}", "TXT")
                for rdata in dmarc_answers:
                    val = str(rdata)
                    if "v=DMARC1" in val:
                        results["dmarc"] = val
            except Exception:
                pass

            for selector in ["default", "google", "mail", "dkim", "selector1", "selector2", "k1"]:
                try:
                    resolver.resolve(f"{selector}._domainkey.{self.domain}", "TXT")
                    results["dkim_selectors"].append(selector)
                except Exception:
                    pass

            for ns in results["ns"]:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns.rstrip("."), self.domain, timeout=self.timeout))
                    for name in zone.nodes.keys():
                        results["zone_transfer"].append(str(name))
                except Exception:
                    pass

            try:
                random_sub = f"phantomrecon-wildcard-{int(time.time())}.{self.domain}"
                resolver.resolve(random_sub, "A")
                results["wildcard"] = True
            except Exception:
                results["wildcard"] = False

            try:
                resolver.resolve(self.domain, "DNSKEY")
                results["dnssec"] = True
            except Exception:
                results["dnssec"] = False

        except ImportError:
            results["error"] = "dnspython not installed"

        return results
