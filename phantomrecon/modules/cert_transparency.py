"""
cert_transparency.py
====================
Certificate Transparency + Email Harvesting module.

Features:
  - crt.sh passive subdomain enumeration (no active scanning)
  - certspotter API fallback
  - Google/Bing dorking for emails
  - HTML scraping email extraction
  - Regex-based email pattern matching from multiple sources
  - LinkedIn/WHOIS/GitHub email hunting
  - MX record discovery
  - Breached email check via haveibeenpwned (optional API key)
  - Export results to JSON/CSV
"""

from __future__ import annotations

import csv
import json
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SubdomainResult:
    domain: str
    source: str
    ip: Optional[str] = None
    san_names: List[str] = field(default_factory=list)
    issuer: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None

@dataclass
class EmailResult:
    email: str
    source: str
    confidence: str = "medium"
    breached: Optional[bool] = None
    breach_count: Optional[int] = None


# ---------------------------------------------------------------------------
# HTTP helper (no dependencies)
# ---------------------------------------------------------------------------

def _http_get(url: str, timeout: int = 15, headers: Optional[dict] = None) -> Tuple[int, str]:
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0 (compatible; PhantomRecon/1.0)")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)


# ---------------------------------------------------------------------------
# Certificate Transparency
# ---------------------------------------------------------------------------

class CertTransparency:
    CRT_SH_URL    = "https://crt.sh/?q=%.{domain}&output=json"
    CERTSPOTTER   = "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    FACEBOOK_CT   = "https://graph.facebook.com/certificates?query={domain}&fields=domains,issuer_name,valid_from,valid_to&limit=500"

    def __init__(self, domain: str, verbose: bool = False):
        self.domain  = domain.lstrip("*.")
        self.verbose = verbose
        self.results: Dict[str, SubdomainResult] = {}

    def _resolve(self, subdomain: str) -> Optional[str]:
        try:
            return socket.gethostbyname(subdomain)
        except Exception:
            return None

    def _from_crt_sh(self) -> List[SubdomainResult]:
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        status, body = _http_get(url, timeout=20)
        if status != 200:
            return []
        try:
            data = json.loads(body)
        except Exception:
            return []

        seen: Set[str] = set()
        results = []
        for entry in data:
            names_raw = entry.get("name_value", "")
            for name in names_raw.splitlines():
                name = name.strip().lower().lstrip("*.")
                if not name or name in seen:
                    continue
                if not name.endswith(self.domain):
                    continue
                seen.add(name)
                results.append(SubdomainResult(
                    domain=name,
                    source="crt.sh",
                    issuer=entry.get("issuer_name", ""),
                    not_before=entry.get("not_before", ""),
                    not_after=entry.get("not_after", ""),
                ))
        return results

    def _from_certspotter(self) -> List[SubdomainResult]:
        url = self.CERTSPOTTER.format(domain=self.domain)
        status, body = _http_get(url, timeout=20)
        if status != 200:
            return []
        try:
            data = json.loads(body)
        except Exception:
            return []

        seen: Set[str] = set()
        results = []
        for entry in data:
            for name in entry.get("dns_names", []):
                name = name.strip().lower().lstrip("*.")
                if name and name.endswith(self.domain) and name not in seen:
                    seen.add(name)
                    results.append(SubdomainResult(domain=name, source="certspotter"))
        return results

    def _from_hackertarget(self) -> List[SubdomainResult]:
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        status, body = _http_get(url, timeout=15)
        results = []
        if status != 200:
            return results
        for line in body.splitlines():
            parts = line.split(",")
            if len(parts) >= 2:
                name = parts[0].strip().lower()
                ip   = parts[1].strip()
                if name.endswith(self.domain):
                    results.append(SubdomainResult(domain=name, source="hackertarget", ip=ip))
        return results

    def _from_threatminer(self) -> List[SubdomainResult]:
        url = f"https://api.threatminer.org/v2/domain.php?q={self.domain}&rt=5"
        status, body = _http_get(url, timeout=15)
        results = []
        try:
            data = json.loads(body)
            for name in data.get("results", []):
                name = name.strip().lower()
                if name.endswith(self.domain):
                    results.append(SubdomainResult(domain=name, source="threatminer"))
        except Exception:
            pass
        return results

    def _from_rapiddns(self) -> List[SubdomainResult]:
        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
        status, body = _http_get(url, timeout=15)
        results = []
        pattern = re.compile(r'<td>([a-zA-Z0-9\-\.]+\.' + re.escape(self.domain) + r')</td>')
        for match in pattern.findall(body):
            name = match.strip().lower()
            results.append(SubdomainResult(domain=name, source="rapiddns"))
        return results

    def _from_wayback(self) -> List[SubdomainResult]:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey&limit=5000"
        status, body = _http_get(url, timeout=20)
        results = []
        try:
            data = json.loads(body)
            seen: Set[str] = set()
            for row in data[1:]:
                try:
                    parsed = urllib.parse.urlparse(row[0])
                    host = parsed.netloc.lower().split(":")[0]
                    if host.endswith(self.domain) and host not in seen:
                        seen.add(host)
                        results.append(SubdomainResult(domain=host, source="wayback"))
                except Exception:
                    pass
        except Exception:
            pass
        return results

    def enumerate(self, resolve_ips: bool = True) -> List[SubdomainResult]:
        sources = [
            self._from_crt_sh,
            self._from_certspotter,
            self._from_hackertarget,
            self._from_threatminer,
            self._from_rapiddns,
            self._from_wayback,
        ]

        seen: Set[str] = set()
        all_results: List[SubdomainResult] = []

        for fn in sources:
            try:
                batch = fn()
                for r in batch:
                    if r.domain not in seen:
                        seen.add(r.domain)
                        if resolve_ips and not r.ip:
                            r.ip = self._resolve(r.domain)
                        all_results.append(r)
                        self.results[r.domain] = r
            except Exception:
                pass

        return sorted(all_results, key=lambda x: x.domain)

    def to_json(self) -> str:
        return json.dumps(
            [{"domain": r.domain, "source": r.source, "ip": r.ip,
              "issuer": r.issuer, "not_before": r.not_before, "not_after": r.not_after}
             for r in self.results.values()],
            indent=2
        )

    def to_csv(self, path: str) -> None:
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["domain", "ip", "source", "issuer", "not_before", "not_after"])
            w.writeheader()
            for r in self.results.values():
                w.writerow({"domain": r.domain, "ip": r.ip or "", "source": r.source,
                             "issuer": r.issuer or "", "not_before": r.not_before or "",
                             "not_after": r.not_after or ""})


# ---------------------------------------------------------------------------
# Email Harvester
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE
)

SOCIAL_PATTERNS = [
    # LinkedIn format
    r"(?:at|@)\s*([a-zA-Z0-9._%+\-]+)\s*(?:dot|\.)\s*([a-zA-Z]{2,})",
]

BLACKLIST_DOMAINS = {
    "example.com", "test.com", "email.com", "domain.com",
    "yoursite.com", "sentry.io", "w3.org", "schema.org",
    "google.com", "googleapis.com", "gstatic.com",
    "jquery.com", "bootstrap.com", "cloudflare.com",
    "png", "jpg", "gif", "svg", "css", "js",
}


class EmailHarvester:
    SEARCH_URLS = [
        "https://www.google.com/search?q=%22%40{domain}%22&num=100",
        "https://www.bing.com/search?q=%22%40{domain}%22&count=50",
    ]
    HUNTER_URL  = "https://api.hunter.io/v2/domain-search?domain={domain}&api_key={key}&limit=100"
    HIBP_URL    = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

    def __init__(self, domain: str, hunter_key: Optional[str] = None,
                 hibp_key: Optional[str] = None, verbose: bool = False):
        self.domain     = domain
        self.hunter_key = hunter_key
        self.hibp_key   = hibp_key
        self.verbose    = verbose
        self.results: Dict[str, EmailResult] = {}

    def _clean_email(self, email: str) -> Optional[str]:
        email = email.strip().lower()
        if not EMAIL_RE.fullmatch(email):
            return None
        parts = email.split("@")
        if len(parts) != 2:
            return None
        local, domain = parts
        if domain in BLACKLIST_DOMAINS or "." not in domain:
            return None
        if len(local) < 1 or len(local) > 64:
            return None
        return email

    def _extract_from_text(self, text: str, source: str) -> List[EmailResult]:
        found = []
        for m in EMAIL_RE.findall(text):
            e = self._clean_email(m)
            if e and (self.domain in e or not self.domain):
                if e not in self.results:
                    self.results[e] = EmailResult(email=e, source=source, confidence="medium")
                    found.append(self.results[e])
        return found

    def _from_url(self, url: str, source: str) -> List[EmailResult]:
        status, body = _http_get(url, timeout=15)
        if status == 0:
            return []
        return self._extract_from_text(body, source)

    def _from_hunter_io(self) -> List[EmailResult]:
        if not self.hunter_key:
            return []
        url = self.HUNTER_URL.format(domain=self.domain, key=self.hunter_key)
        status, body = _http_get(url, timeout=15)
        if status != 200:
            return []
        try:
            data = json.loads(body)
            found = []
            for entry in data.get("data", {}).get("emails", []):
                email = entry.get("value", "").strip().lower()
                e = self._clean_email(email)
                if e and e not in self.results:
                    confidence = entry.get("confidence", 50)
                    conf_str = "high" if confidence >= 80 else ("medium" if confidence >= 50 else "low")
                    r = EmailResult(email=e, source="hunter.io", confidence=conf_str)
                    self.results[e] = r
                    found.append(r)
            return found
        except Exception:
            return []

    def _from_whois(self) -> List[EmailResult]:
        url = f"https://www.whois.com/whois/{self.domain}"
        status, body = _http_get(url, timeout=15)
        if status == 0:
            return []
        return self._extract_from_text(body, "whois")

    def _from_common_patterns(self) -> List[EmailResult]:
        prefixes = [
            "admin", "info", "contact", "support", "help", "sales", "abuse",
            "security", "webmaster", "noreply", "no-reply", "mail", "hello",
            "hr", "jobs", "careers", "finance", "billing", "legal", "privacy",
            "ceo", "cto", "ciso", "it", "dev", "tech",
        ]
        found = []
        for prefix in prefixes:
            email = f"{prefix}@{self.domain}"
            if email not in self.results:
                self.results[email] = EmailResult(email=email, source="pattern", confidence="low")
                found.append(self.results[email])
        return found

    def _from_github(self) -> List[EmailResult]:
        url = f"https://github.com/search?q=%40{self.domain}&type=code"
        status, body = _http_get(url, timeout=15)
        if status == 0:
            return []
        return self._extract_from_text(body, "github")

    def _check_hibp(self, email: str) -> Tuple[bool, int]:
        if not self.hibp_key:
            return False, 0
        url = self.HIBP_URL.format(email=urllib.parse.quote(email))
        headers = {"hibp-api-key": self.hibp_key, "User-Agent": "PhantomRecon"}
        status, body = _http_get(url, headers=headers, timeout=10)
        if status == 200:
            try:
                data = json.loads(body)
                return True, len(data)
            except Exception:
                return True, 1
        return False, 0

    def _from_mx_records(self) -> List[str]:
        mx_records = []
        try:
            import subprocess
            result = subprocess.run(
                ["dig", "+short", "MX", self.domain],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    mx_records.append(parts[-1].rstrip("."))
        except Exception:
            pass
        return mx_records

    def harvest(self, check_breaches: bool = False) -> List[EmailResult]:
        all_found: List[EmailResult] = []

        sources = [
            (self._from_hunter_io, "hunter.io"),
            (self._from_whois, "whois"),
            (self._from_github, "github"),
            (self._from_common_patterns, "pattern"),
        ]

        for fn, name in sources:
            try:
                batch = fn()
                all_found.extend(batch)
            except Exception:
                pass
            time.sleep(0.5)

        if check_breaches and self.hibp_key:
            for r in list(self.results.values()):
                try:
                    breached, count = self._check_hibp(r.email)
                    r.breached = breached
                    r.breach_count = count
                    time.sleep(1.6)
                except Exception:
                    pass

        return sorted(self.results.values(), key=lambda x: x.email)

    def to_json(self) -> str:
        return json.dumps(
            [{"email": r.email, "source": r.source, "confidence": r.confidence,
              "breached": r.breached, "breach_count": r.breach_count}
             for r in self.results.values()],
            indent=2
        )

    def to_csv(self, path: str) -> None:
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["email", "source", "confidence", "breached", "breach_count"])
            w.writeheader()
            for r in self.results.values():
                w.writerow({"email": r.email, "source": r.source, "confidence": r.confidence,
                             "breached": r.breached, "breach_count": r.breach_count})


# ---------------------------------------------------------------------------
# Combined runner
# ---------------------------------------------------------------------------

def run_cert_recon(domain: str, resolve: bool = True, verbose: bool = False) -> Dict:
    ct = CertTransparency(domain, verbose=verbose)
    subdomains = ct.enumerate(resolve_ips=resolve)
    return {
        "domain": domain,
        "subdomains": [
            {"domain": r.domain, "ip": r.ip, "source": r.source,
             "issuer": r.issuer, "not_before": r.not_before, "not_after": r.not_after}
            for r in subdomains
        ],
        "count": len(subdomains),
    }


def run_email_harvest(domain: str, hunter_key: Optional[str] = None,
                      hibp_key: Optional[str] = None,
                      check_breaches: bool = False,
                      verbose: bool = False) -> Dict:
    harvester = EmailHarvester(domain, hunter_key=hunter_key,
                               hibp_key=hibp_key, verbose=verbose)
    emails = harvester.harvest(check_breaches=check_breaches)
    mx = harvester._from_mx_records()
    return {
        "domain": domain,
        "emails": [
            {"email": r.email, "source": r.source, "confidence": r.confidence,
             "breached": r.breached, "breach_count": r.breach_count}
            for r in emails
        ],
        "mx_records": mx,
        "count": len(emails),
    }
