"""
nuclei_runner.py
================
Nuclei Template Runner (embedded in PhantomRecon):
  - Runs .yaml Nuclei templates directly via subprocess
  - Falls back to pure-Python template interpreter for simple cases
  - Supports: http, network, file, dns, headless matchers
  - Template discovery from ~/.phantomrecon/templates/ and built-in set
  - Severity filtering (critical, high, medium, low, info)
  - Tag filtering (cve, rce, sqli, xss, lfi, ssrf, etc.)
  - Built-in mini-template set (common vulns, misconfigs, exposures)
  - JSON/JSONL output parsing
  - Concurrency control (rate-limit, bulk-size)
  - Template auto-update from ProjectDiscovery (optional)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class NucleiResult:
    template_id:  str
    name:         str
    severity:     str
    url:          str
    matched:      str
    matcher_name: str = ""
    extracted:    List[str] = field(default_factory=list)
    curl_cmd:     Optional[str] = None
    tags:         List[str] = field(default_factory=list)
    description:  str = ""
    reference:    List[str] = field(default_factory=list)
    cvss_score:   Optional[float] = None
    cve_id:       Optional[str] = None


# ---------------------------------------------------------------------------
# Nuclei binary runner
# ---------------------------------------------------------------------------

class NucleiBinaryRunner:
    def __init__(self, nuclei_path: Optional[str] = None):
        self.nuclei_path = nuclei_path or shutil.which("nuclei") or "nuclei"
        self.available   = shutil.which(self.nuclei_path) is not None or \
                           Path(self.nuclei_path).exists()

    def run(
        self,
        target:     str,
        templates:  Optional[List[str]] = None,
        tags:       Optional[List[str]] = None,
        severity:   Optional[List[str]] = None,
        exclude_tags: Optional[List[str]] = None,
        rate_limit: int = 150,
        bulk_size:  int = 25,
        concurrency: int = 25,
        timeout:    int = 5,
        retries:    int = 1,
        proxy:      Optional[str] = None,
        extra_args: Optional[List[str]] = None,
        output_file: Optional[str] = None,
    ) -> List[NucleiResult]:
        if not self.available:
            return []

        cmd = [self.nuclei_path, "-u", target, "-json", "-silent", "-no-color"]
        cmd += ["-rl", str(rate_limit), "-bs", str(bulk_size), "-c", str(concurrency)]
        cmd += ["-timeout", str(timeout), "-retries", str(retries)]

        if templates:
            for t in templates:
                cmd += ["-t", t]
        else:
            cmd += ["-t", "~/.nuclei-templates/"]

        if tags:
            cmd += ["-tags", ",".join(tags)]
        if severity:
            cmd += ["-severity", ",".join(severity)]
        if exclude_tags:
            cmd += ["-etags", ",".join(exclude_tags)]
        if proxy:
            cmd += ["-proxy", proxy]
        if output_file:
            cmd += ["-o", output_file]
        if extra_args:
            cmd.extend(extra_args)

        results = []
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    results.append(NucleiResult(
                        template_id  = data.get("template-id", ""),
                        name         = info.get("name", ""),
                        severity     = info.get("severity", "info"),
                        url          = data.get("matched-at", data.get("host", "")),
                        matched      = data.get("matched-at", ""),
                        matcher_name = data.get("matcher-name", ""),
                        extracted    = data.get("extracted-results", []),
                        curl_cmd     = data.get("curl-command", None),
                        tags         = info.get("tags", []),
                        description  = info.get("description", ""),
                        reference    = info.get("reference", []),
                        cvss_score   = info.get("classification", {}).get("cvss-score"),
                        cve_id       = (info.get("classification", {}).get("cve-id") or
                                        data.get("template-id", "").upper()
                                        if re.match(r"cve-\d{4}-\d+",
                                                    data.get("template-id", ""), re.I) else None),
                    ))
                except json.JSONDecodeError:
                    pass
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            pass

        return results

    def update_templates(self) -> bool:
        if not self.available:
            return False
        try:
            proc = subprocess.run(
                [self.nuclei_path, "-update-templates"],
                capture_output=True, text=True, timeout=120,
            )
            return proc.returncode == 0
        except Exception:
            return False

    def list_templates(self, tags: Optional[List[str]] = None,
                       severity: Optional[List[str]] = None) -> List[str]:
        if not self.available:
            return []
        cmd = [self.nuclei_path, "-tl", "-json"]
        if tags:
            cmd += ["-tags", ",".join(tags)]
        if severity:
            cmd += ["-severity", ",".join(severity)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            templates = []
            for line in proc.stdout.splitlines():
                try:
                    data = json.loads(line)
                    templates.append(data.get("template", ""))
                except Exception:
                    if line.strip():
                        templates.append(line.strip())
            return templates
        except Exception:
            return []


# ---------------------------------------------------------------------------
# Built-in Pure-Python Template Interpreter (for when nuclei binary not available)
# ---------------------------------------------------------------------------

BUILTIN_TEMPLATES = [
    {
        "id":       "http-missing-security-headers",
        "name":     "Missing Security Headers",
        "severity": "info",
        "tags":     ["misconfig", "headers"],
        "checks": [
            {"type": "header_missing", "header": "X-Frame-Options",            "evidence": "Missing X-Frame-Options — clickjacking possible"},
            {"type": "header_missing", "header": "Content-Security-Policy",    "evidence": "Missing Content-Security-Policy — XSS risk"},
            {"type": "header_missing", "header": "X-Content-Type-Options",     "evidence": "Missing X-Content-Type-Options — MIME sniffing"},
            {"type": "header_missing", "header": "Strict-Transport-Security",  "evidence": "Missing HSTS — HTTPS not enforced"},
            {"type": "header_missing", "header": "Referrer-Policy",            "evidence": "Missing Referrer-Policy"},
            {"type": "header_missing", "header": "Permissions-Policy",         "evidence": "Missing Permissions-Policy"},
        ],
    },
    {
        "id":       "exposed-git-directory",
        "name":     "Exposed .git Directory",
        "severity": "high",
        "tags":     ["exposure", "git"],
        "checks": [
            {"type": "path_probe", "path": "/.git/HEAD",
             "status": 200, "body_match": r"ref: refs/heads|[0-9a-f]{40}",
             "evidence": "Git repository HEAD exposed — source code disclosure"},
            {"type": "path_probe", "path": "/.git/config",
             "status": 200, "body_match": r"\[core\]",
             "evidence": "Git config file exposed"},
        ],
    },
    {
        "id":       "exposed-env-file",
        "name":     "Exposed .env File",
        "severity": "critical",
        "tags":     ["exposure", "env", "secrets"],
        "checks": [
            {"type": "path_probe", "path": "/.env",
             "status": 200, "body_match": r"DB_|APP_|SECRET|PASSWORD|KEY|TOKEN",
             "evidence": ".env file exposed — credentials in plaintext"},
            {"type": "path_probe", "path": "/.env.local",
             "status": 200, "body_match": r"=",
             "evidence": ".env.local file exposed"},
            {"type": "path_probe", "path": "/.env.production",
             "status": 200, "body_match": r"=",
             "evidence": ".env.production exposed"},
            {"type": "path_probe", "path": "/.env.backup",
             "status": 200, "body_match": r"=",
             "evidence": ".env.backup exposed"},
        ],
    },
    {
        "id":       "directory-listing",
        "name":     "Directory Listing Enabled",
        "severity": "medium",
        "tags":     ["misconfig", "exposure"],
        "checks": [
            {"type": "body_match",
             "body_match": r"index of /|directory listing|parent directory",
             "evidence": "Directory listing enabled — file enumeration possible"},
        ],
    },
    {
        "id":       "wp-debug-log",
        "name":     "WordPress Debug Log Exposed",
        "severity": "medium",
        "tags":     ["wordpress", "exposure"],
        "checks": [
            {"type": "path_probe", "path": "/wp-content/debug.log",
             "status": 200, "body_match": r"PHP|WordPress|Fatal error|Warning:",
             "evidence": "WordPress debug.log exposed — error details leaked"},
        ],
    },
    {
        "id":       "php-info-exposed",
        "name":     "PHP Info Page Exposed",
        "severity": "medium",
        "tags":     ["exposure", "php"],
        "checks": [
            {"type": "path_probe", "path": "/phpinfo.php",
             "status": 200, "body_match": r"PHP Version|phpinfo\(\)|PHP Extension",
             "evidence": "phpinfo() exposed — server configuration disclosed"},
            {"type": "path_probe", "path": "/info.php",
             "status": 200, "body_match": r"PHP Version|phpinfo",
             "evidence": "PHP info page exposed"},
        ],
    },
    {
        "id":       "exposed-backup-files",
        "name":     "Exposed Backup Files",
        "severity": "high",
        "tags":     ["exposure", "backup"],
        "checks": [
            {"type": "path_probe", "path": "/backup.zip",    "status": 200, "body_match": r"PK", "evidence": "backup.zip exposed"},
            {"type": "path_probe", "path": "/backup.tar.gz", "status": 200, "body_match": r"",   "evidence": "backup.tar.gz exposed"},
            {"type": "path_probe", "path": "/db.sql",        "status": 200, "body_match": r"CREATE TABLE|INSERT INTO", "evidence": "SQL dump exposed"},
            {"type": "path_probe", "path": "/dump.sql",      "status": 200, "body_match": r"CREATE TABLE", "evidence": "SQL dump exposed"},
            {"type": "path_probe", "path": "/database.sql",  "status": 200, "body_match": r"CREATE TABLE", "evidence": "SQL dump exposed"},
            {"type": "path_probe", "path": "/config.bak",    "status": 200, "body_match": r"",   "evidence": "Config backup exposed"},
        ],
    },
    {
        "id":       "exposed-admin-panels",
        "name":     "Exposed Admin Panels",
        "severity": "high",
        "tags":     ["exposure", "admin"],
        "checks": [
            {"type": "path_probe", "path": "/admin",         "status": 200, "body_match": r"admin|login|dashboard", "evidence": "Admin panel exposed at /admin"},
            {"type": "path_probe", "path": "/admin/login",   "status": 200, "body_match": r"login|password",       "evidence": "Admin login exposed"},
            {"type": "path_probe", "path": "/wp-admin",      "status": 200, "body_match": r"wordpress|wp-admin",   "evidence": "WordPress admin exposed"},
            {"type": "path_probe", "path": "/phpmyadmin",    "status": 200, "body_match": r"phpMyAdmin|mysql",     "evidence": "phpMyAdmin exposed"},
            {"type": "path_probe", "path": "/.env",          "status": 200, "body_match": r"",                    "evidence": ".env exposed"},
        ],
    },
    {
        "id":       "exposed-api-keys",
        "name":     "Exposed API Keys in Response",
        "severity": "critical",
        "tags":     ["exposure", "secrets", "api"],
        "checks": [
            {"type": "body_match",
             "body_match": r"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|sk-[a-zA-Z0-9]{48}|ghp_[a-zA-Z0-9]{36}",
             "evidence": "AWS/Google/OpenAI/GitHub API key pattern detected in response"},
        ],
    },
    {
        "id":       "cors-misconfiguration",
        "name":     "CORS Misconfiguration",
        "severity": "medium",
        "tags":     ["misconfig", "cors"],
        "checks": [
            {"type": "header_value", "header": "Access-Control-Allow-Origin", "value_match": r"^(\*|null)$",
             "evidence": "CORS allows all origins or null — potential CORS exploit"},
        ],
    },
    {
        "id":       "server-version-disclosure",
        "name":     "Server Version Disclosed",
        "severity": "info",
        "tags":     ["disclosure", "server"],
        "checks": [
            {"type": "header_match", "header": "Server",
             "body_match": r"Apache/\d|nginx/\d|IIS/\d|PHP/\d",
             "evidence": "Server version disclosed in headers"},
        ],
    },
]


# ---------------------------------------------------------------------------
# Pure-Python template executor
# ---------------------------------------------------------------------------

def _http_get(url: str, headers_extra: Optional[Dict] = None,
              timeout: float = 8.0) -> Tuple[int, str, Dict]:
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 PhantomRecon/1.0")
        if headers_extra:
            for k, v in headers_extra.items():
                req.add_header(k, v)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(65536).decode("utf-8", errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(4096).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, body, dict(e.headers) if e.headers else {}
    except Exception as e:
        return 0, str(e), {}


class PythonTemplateRunner:
    def run(self, target: str,
            tags_filter: Optional[List[str]] = None,
            severity_filter: Optional[List[str]] = None) -> List[NucleiResult]:
        results = []
        base = target.rstrip("/")

        base_code, base_body, base_headers = _http_get(base)
        base_headers_lower = {k.lower(): v for k, v in base_headers.items()}

        for tmpl in BUILTIN_TEMPLATES:
            if tags_filter and not any(t in tmpl.get("tags", []) for t in tags_filter):
                continue
            if severity_filter and tmpl.get("severity", "info") not in severity_filter:
                continue

            for check in tmpl.get("checks", []):
                check_type = check["type"]
                found      = False
                evidence   = check.get("evidence", "")

                if check_type == "header_missing":
                    hdr = check["header"].lower()
                    if hdr not in base_headers_lower:
                        found = True

                elif check_type == "header_value":
                    hdr = check["header"].lower()
                    val = base_headers_lower.get(hdr, "")
                    if re.search(check.get("value_match", ""), val, re.IGNORECASE):
                        found = True

                elif check_type == "header_match":
                    hdr = check["header"].lower()
                    val = base_headers_lower.get(hdr, "")
                    if re.search(check.get("body_match", ""), val, re.IGNORECASE):
                        found = True

                elif check_type == "body_match":
                    if re.search(check["body_match"], base_body, re.IGNORECASE):
                        found = True

                elif check_type == "path_probe":
                    probe_url  = base + check["path"]
                    code, body, hdrs = _http_get(probe_url)
                    if code == check.get("status", 200):
                        bm = check.get("body_match", "")
                        if not bm or re.search(bm, body, re.IGNORECASE):
                            found    = True
                            evidence = check.get("evidence", "") + f" ({probe_url})"

                if found:
                    results.append(NucleiResult(
                        template_id  = tmpl["id"],
                        name         = tmpl["name"],
                        severity     = tmpl.get("severity", "info"),
                        url          = base,
                        matched      = base,
                        tags         = tmpl.get("tags", []),
                        description  = tmpl.get("name", ""),
                        evidence     = evidence,
                    ))
                    break

        return results


# ---------------------------------------------------------------------------
# Master Nuclei Runner (auto-selects binary or pure-Python)
# ---------------------------------------------------------------------------

class NucleiRunner:
    def __init__(self, nuclei_path: Optional[str] = None,
                 templates_dir: Optional[str] = None):
        self.binary   = NucleiBinaryRunner(nuclei_path)
        self.python   = PythonTemplateRunner()
        self.tmpl_dir = templates_dir or str(Path.home() / ".nuclei-templates")

    def run(
        self,
        target:    str,
        templates: Optional[List[str]] = None,
        tags:      Optional[List[str]] = None,
        severity:  Optional[List[str]] = None,
        use_binary: bool = True,
        rate_limit: int = 150,
        concurrency: int = 25,
        proxy:     Optional[str] = None,
    ) -> List[NucleiResult]:
        if use_binary and self.binary.available:
            return self.binary.run(
                target=target,
                templates=templates or [self.tmpl_dir],
                tags=tags,
                severity=severity,
                rate_limit=rate_limit,
                concurrency=concurrency,
                proxy=proxy,
            )
        return self.python.run(target, tags, severity)

    def run_custom_template_file(self, target: str, template_path: str) -> List[NucleiResult]:
        if self.binary.available:
            return self.binary.run(target=target, templates=[template_path])
        return []

    def auto_run(self, target: str) -> Dict:
        results = self.run(target)
        by_severity: Dict[str, List] = {}
        for r in results:
            by_severity.setdefault(r.severity, []).append({
                "id":       r.template_id,
                "name":     r.name,
                "url":      r.url,
                "matched":  r.matched,
                "tags":     r.tags,
                "evidence": getattr(r, "evidence", r.description),
                "cve":      r.cve_id,
                "cvss":     r.cvss_score,
            })
        return {
            "target":     target,
            "total":      len(results),
            "by_severity": by_severity,
            "binary_used": self.binary.available,
        }
