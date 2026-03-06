"""
threat_intel.py
===============
Threat Intelligence & Reporting Engine:
  - VirusTotal enrichment (IP/domain/URL/hash)
  - AbuseIPDB reputation check
  - Shodan host lookup
  - MITRE ATT&CK technique tagging
  - Timeline attack graph generation (kill-chain)
  - Diff-based regression scanner (new findings vs baseline)
  - Executive + Technical dual report (JSON/HTML/text)
  - Threat score aggregation
"""

from __future__ import annotations

import datetime
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping
# ---------------------------------------------------------------------------

MITRE_TECHNIQUES: Dict[str, Dict] = {
    "T1190": {"name": "Exploit Public-Facing Application",      "tactic": "Initial Access"},
    "T1059": {"name": "Command and Scripting Interpreter",      "tactic": "Execution"},
    "T1059.007": {"name": "JavaScript",                         "tactic": "Execution"},
    "T1078": {"name": "Valid Accounts",                         "tactic": "Defense Evasion / Persistence"},
    "T1083": {"name": "File and Directory Discovery",           "tactic": "Discovery"},
    "T1090": {"name": "Proxy",                                  "tactic": "Command and Control"},
    "T1110": {"name": "Brute Force",                            "tactic": "Credential Access"},
    "T1110.001": {"name": "Password Guessing",                  "tactic": "Credential Access"},
    "T1110.003": {"name": "Password Spraying",                  "tactic": "Credential Access"},
    "T1133": {"name": "External Remote Services",               "tactic": "Initial Access"},
    "T1185": {"name": "Browser Session Hijacking",              "tactic": "Collection"},
    "T1190": {"name": "Exploit Public-Facing Application",      "tactic": "Initial Access"},
    "T1210": {"name": "Exploitation of Remote Services",        "tactic": "Lateral Movement"},
    "T1212": {"name": "Exploitation for Credential Access",     "tactic": "Credential Access"},
    "T1505.003": {"name": "Web Shell",                          "tactic": "Persistence"},
    "T1552": {"name": "Unsecured Credentials",                  "tactic": "Credential Access"},
    "T1552.001": {"name": "Credentials In Files",               "tactic": "Credential Access"},
    "T1566": {"name": "Phishing",                               "tactic": "Initial Access"},
    "T1566.002": {"name": "Spearphishing Link",                 "tactic": "Initial Access"},
    "T1592": {"name": "Gather Victim Host Information",         "tactic": "Reconnaissance"},
    "T1592.002": {"name": "Software",                           "tactic": "Reconnaissance"},
    "T1595": {"name": "Active Scanning",                        "tactic": "Reconnaissance"},
    "T1596": {"name": "Search Open Technical Databases",        "tactic": "Reconnaissance"},
    "T1598": {"name": "Phishing for Information",               "tactic": "Reconnaissance"},
}

VULN_TO_MITRE: Dict[str, List[str]] = {
    "rce":                   ["T1190", "T1059"],
    "sql_injection":         ["T1190"],
    "sqli":                  ["T1190"],
    "xss":                   ["T1059.007"],
    "ssrf":                  ["T1090"],
    "lfi":                   ["T1083"],
    "path_traversal":        ["T1083"],
    "deserialization":       ["T1190"],
    "xxe":                   ["T1190"],
    "authentication_bypass": ["T1078"],
    "password_spray":        ["T1110.003"],
    "brute_force":           ["T1110.001"],
    "open_redirect":         ["T1566.002"],
    "csrf":                  ["T1185"],
    "web_shell":             ["T1505.003"],
    "information_disclosure":["T1592"],
    "credentials_exposed":   ["T1552.001"],
    "jwt_attack":            ["T1078"],
    "oauth_attack":          ["T1078"],
    "2fa_bypass":            ["T1078"],
}


def tag_mitre(vuln_type: str) -> List[Dict]:
    vtype = vuln_type.lower().replace("-", "_").replace(" ", "_")
    ids   = VULN_TO_MITRE.get(vtype, [])
    result = []
    for tid in ids:
        tech = MITRE_TECHNIQUES.get(tid, {})
        result.append({"id": tid, "name": tech.get("name", tid), "tactic": tech.get("tactic", "")})
    return result


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _api_get(url: str, headers: Optional[Dict] = None, timeout: float = 10.0) -> Tuple[int, Dict]:
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "PhantomRecon/1.0")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, json.loads(r.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = {}
        return e.code, body
    except Exception as e:
        return 0, {"error": str(e)}


# ---------------------------------------------------------------------------
# VirusTotal Enrichment
# ---------------------------------------------------------------------------

class VirusTotalEnricher:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}

    def lookup_ip(self, ip: str) -> Dict:
        code, data = _api_get(f"{self.BASE}/ip_addresses/{ip}", self.headers)
        if code == 200:
            attrs = data.get("data", {}).get("attributes", {})
            return {
                "ip":           ip,
                "country":      attrs.get("country", ""),
                "asn":          attrs.get("asn", ""),
                "as_owner":     attrs.get("as_owner", ""),
                "malicious":    attrs.get("last_analysis_stats", {}).get("malicious", 0),
                "harmless":     attrs.get("last_analysis_stats", {}).get("harmless", 0),
                "reputation":   attrs.get("reputation", 0),
                "tags":         attrs.get("tags", []),
            }
        return {"ip": ip, "error": f"HTTP {code}"}

    def lookup_domain(self, domain: str) -> Dict:
        code, data = _api_get(f"{self.BASE}/domains/{domain}", self.headers)
        if code == 200:
            attrs = data.get("data", {}).get("attributes", {})
            return {
                "domain":      domain,
                "registrar":   attrs.get("registrar", ""),
                "creation_date": attrs.get("creation_date", ""),
                "malicious":   attrs.get("last_analysis_stats", {}).get("malicious", 0),
                "reputation":  attrs.get("reputation", 0),
                "categories":  attrs.get("categories", {}),
            }
        return {"domain": domain, "error": f"HTTP {code}"}

    def lookup_url(self, url: str) -> Dict:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        code, data = _api_get(f"{self.BASE}/urls/{url_id}", self.headers)
        if code == 200:
            attrs = data.get("data", {}).get("attributes", {})
            return {
                "url":        url,
                "malicious":  attrs.get("last_analysis_stats", {}).get("malicious", 0),
                "phishing":   "phishing" in str(attrs.get("categories", {})).lower(),
                "final_url":  attrs.get("last_final_url", ""),
            }
        return {"url": url, "error": f"HTTP {code}"}

    def lookup_hash(self, file_hash: str) -> Dict:
        code, data = _api_get(f"{self.BASE}/files/{file_hash}", self.headers)
        if code == 200:
            attrs = data.get("data", {}).get("attributes", {})
            return {
                "hash":      file_hash,
                "name":      attrs.get("meaningful_name", ""),
                "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                "type":      attrs.get("type_description", ""),
                "size":      attrs.get("size", 0),
            }
        return {"hash": file_hash, "error": f"HTTP {code}"}


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

class AbuseIPDB:
    BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def check_ip(self, ip: str, max_age_days: int = 90) -> Dict:
        url = f"{self.BASE}/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays={max_age_days}&verbose"
        headers = {"Key": self.api_key, "Accept": "application/json"}
        code, data = _api_get(url, headers)
        if code == 200:
            d = data.get("data", {})
            return {
                "ip":             ip,
                "abuse_score":    d.get("abuseConfidenceScore", 0),
                "country":        d.get("countryCode", ""),
                "usage_type":     d.get("usageType", ""),
                "isp":            d.get("isp", ""),
                "domain":         d.get("domain", ""),
                "total_reports":  d.get("totalReports", 0),
                "is_tor":         d.get("isTor", False),
                "is_public":      d.get("isPublic", True),
            }
        return {"ip": ip, "error": f"HTTP {code}"}


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------

class ShodanEnricher:
    BASE = "https://api.shodan.io"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def host_info(self, ip: str) -> Dict:
        url = f"{self.BASE}/shodan/host/{ip}?key={self.api_key}"
        code, data = _api_get(url)
        if code == 200:
            return {
                "ip":       ip,
                "org":      data.get("org", ""),
                "os":       data.get("os", ""),
                "country":  data.get("country_name", ""),
                "city":     data.get("city", ""),
                "open_ports": data.get("ports", []),
                "hostnames":  data.get("hostnames", []),
                "vulns":      list(data.get("vulns", {}).keys()),
                "tags":       data.get("tags", []),
                "services":   [{"port": s.get("port"), "product": s.get("product", ""),
                                 "version": s.get("version", "")}
                                for s in data.get("data", [])],
            }
        return {"ip": ip, "error": f"HTTP {code}"}

    def search(self, query: str, page: int = 1) -> Dict:
        url = f"{self.BASE}/shodan/host/search?key={self.api_key}&query={urllib.parse.quote(query)}&page={page}"
        code, data = _api_get(url)
        if code == 200:
            return {
                "total":   data.get("total", 0),
                "results": [{"ip": m.get("ip_str"), "port": m.get("port"),
                              "org": m.get("org", ""), "product": m.get("product", "")}
                             for m in data.get("matches", [])],
            }
        return {"error": f"HTTP {code}"}


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    title:       str
    severity:    str
    url:         str
    module:      str
    description: str
    evidence:    str = ""
    recommendation: str = ""
    cve:         Optional[str] = None
    cvss:        Optional[float] = None
    mitre:       List[Dict] = field(default_factory=list)
    timestamp:   str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())


# ---------------------------------------------------------------------------
# Timeline Attack Graph
# ---------------------------------------------------------------------------

KILL_CHAIN_PHASES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command & Control",
    "Actions on Objectives",
]

MODULE_TO_PHASE: Dict[str, str] = {
    "cert_transparency": "Reconnaissance",
    "port_scanner":      "Reconnaissance",
    "network_recon":     "Reconnaissance",
    "dns_advanced":      "Reconnaissance",
    "fingerprint":       "Reconnaissance",
    "nuclei_runner":     "Delivery",
    "vuln_scanner":      "Exploitation",
    "exploit_confirm":   "Exploitation",
    "sql_injection":     "Exploitation",
    "xss":               "Exploitation",
    "rce":               "Exploitation",
    "deserialization":   "Exploitation",
    "jwt_attack":        "Exploitation",
    "oauth_attack":      "Exploitation",
    "2fa_bypass":        "Exploitation",
    "password_spray":    "Credential Access",
    "john":              "Credential Access",
    "payload_gen":       "Installation",
    "web_shell":         "Installation",
    "protocol_fuzz":     "Actions on Objectives",
}


class TimelineGraphBuilder:
    def __init__(self):
        self.events: List[Dict] = []

    def add_event(self, module: str, description: str, timestamp: Optional[str] = None,
                  severity: str = "info") -> None:
        self.events.append({
            "timestamp": timestamp or datetime.datetime.utcnow().isoformat(),
            "module":    module,
            "phase":     MODULE_TO_PHASE.get(module, "Unknown"),
            "description": description,
            "severity":  severity,
        })

    def build_timeline(self) -> Dict:
        phases: Dict[str, List] = {p: [] for p in KILL_CHAIN_PHASES}
        phases["Unknown"] = []
        for ev in sorted(self.events, key=lambda x: x["timestamp"]):
            phase = ev.get("phase", "Unknown")
            phases.setdefault(phase, []).append(ev)
        return {
            "total_events": len(self.events),
            "phases":       phases,
            "timeline":     sorted(self.events, key=lambda x: x["timestamp"]),
        }

    def render_ascii(self) -> str:
        timeline = self.build_timeline()
        lines = ["=" * 60, "  ATTACK TIMELINE — KILL CHAIN VIEW", "=" * 60]
        for phase in KILL_CHAIN_PHASES:
            events = timeline["phases"].get(phase, [])
            if events:
                lines.append(f"\n[{phase.upper()}]")
                for ev in events:
                    sev_icon = {"critical": "!!", "high": "!", "medium": "~", "low": "-", "info": "i"}.get(ev["severity"], " ")
                    lines.append(f"  [{sev_icon}] {ev['timestamp'][:19]} | {ev['module']:20s} | {ev['description']}")
        lines.append("=" * 60)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Regression / Diff Scanner
# ---------------------------------------------------------------------------

class RegressionScanner:
    def __init__(self, baseline_path: Optional[str] = None):
        default_dir = Path.home() / ".phantomrecon"
        default_dir.mkdir(parents=True, exist_ok=True)
        self.baseline_path = baseline_path or str(default_dir / "baseline_findings.json")

    def save_baseline(self, findings: List[Dict]) -> None:
        with open(self.baseline_path, "w") as f:
            json.dump({"timestamp": datetime.datetime.utcnow().isoformat(),
                       "findings": findings}, f, indent=2)

    def load_baseline(self) -> List[Dict]:
        try:
            with open(self.baseline_path) as f:
                data = json.load(f)
            return data.get("findings", [])
        except FileNotFoundError:
            return []

    def diff(self, new_findings: List[Dict]) -> Dict:
        old = self.load_baseline()
        old_keys = {f"{f.get('title','')}|{f.get('url','')}|{f.get('severity','')}" for f in old}
        new_keys = {f"{f.get('title','')}|{f.get('url','')}|{f.get('severity','')}" for f in new_findings}

        new_issues    = [f for f in new_findings
                         if f"{f.get('title','')}|{f.get('url','')}|{f.get('severity','')}" not in old_keys]
        resolved      = [f for f in old
                         if f"{f.get('title','')}|{f.get('url','')}|{f.get('severity','')}" not in new_keys]
        unchanged     = [f for f in new_findings
                         if f"{f.get('title','')}|{f.get('url','')}|{f.get('severity','')}" in old_keys]

        return {
            "new":       new_issues,
            "resolved":  resolved,
            "unchanged": unchanged,
            "summary": {
                "new_count":      len(new_issues),
                "resolved_count": len(resolved),
                "unchanged_count": len(unchanged),
                "regression": len(new_issues) > 0,
            },
        }


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high":     "#fd7e14",
    "medium":   "#ffc107",
    "low":      "#28a745",
    "info":     "#17a2b8",
}


class ReportGenerator:
    def __init__(self, target: str, findings: List[Dict],
                 scan_start: Optional[str] = None,
                 scan_end: Optional[str] = None):
        self.target     = target
        self.findings   = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 99))
        self.scan_start = scan_start or datetime.datetime.utcnow().isoformat()
        self.scan_end   = scan_end   or datetime.datetime.utcnow().isoformat()

    def _severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def generate_json(self, output_path: Optional[str] = None) -> str:
        data = {
            "meta": {
                "tool":       "PhantomRecon",
                "target":     self.target,
                "scan_start": self.scan_start,
                "scan_end":   self.scan_end,
                "generated":  datetime.datetime.utcnow().isoformat(),
            },
            "summary": self._severity_counts(),
            "findings": self.findings,
        }
        out = json.dumps(data, indent=2, default=str)
        if output_path:
            with open(output_path, "w") as f:
                f.write(out)
        return out

    def generate_text(self) -> str:
        lines = [
            "=" * 70,
            f"  PHANTOMRECON SECURITY REPORT",
            f"  Target:  {self.target}",
            f"  Scanned: {self.scan_start[:19]} → {self.scan_end[:19]}",
            "=" * 70,
            "",
            "EXECUTIVE SUMMARY",
            "-" * 70,
        ]
        counts = self._severity_counts()
        for sev in ("critical", "high", "medium", "low", "info"):
            c = counts.get(sev, 0)
            if c:
                bar = "█" * min(c, 40)
                lines.append(f"  {sev.upper():10s} {c:3d}  {bar}")
        lines.append(f"\n  Total Findings: {len(self.findings)}")
        lines.append("")

        lines.append("TECHNICAL FINDINGS")
        lines.append("-" * 70)
        for i, f in enumerate(self.findings, 1):
            sev  = f.get("severity", "info").upper()
            title = f.get("title", "Unknown")
            url   = f.get("url", "")
            desc  = f.get("description", "")
            evid  = f.get("evidence", "")
            rec   = f.get("recommendation", "")
            mitre = f.get("mitre", [])
            cve   = f.get("cve", "")
            cvss  = f.get("cvss", "")

            lines.append(f"\n[{i}] [{sev}] {title}")
            if url:   lines.append(f"    URL:       {url}")
            if cve:   lines.append(f"    CVE:       {cve}")
            if cvss:  lines.append(f"    CVSS:      {cvss}")
            if desc:  lines.append(f"    Detail:    {desc}")
            if evid:  lines.append(f"    Evidence:  {evid[:200]}")
            if rec:   lines.append(f"    Fix:       {rec}")
            if mitre:
                ids = ", ".join(f"{m['id']} ({m['name']})" for m in mitre)
                lines.append(f"    MITRE:     {ids}")
        lines.append("\n" + "=" * 70)
        return "\n".join(lines)

    def generate_html(self, output_path: Optional[str] = None) -> str:
        counts = self._severity_counts()
        summary_rows = "".join(
            f'<tr><td><span class="badge" style="background:{SEVERITY_COLORS.get(s,"#888")}">{s.upper()}</span></td>'
            f'<td>{counts.get(s,0)}</td></tr>'
            for s in ("critical", "high", "medium", "low", "info")
        )
        finding_cards = ""
        for f in self.findings:
            sev    = f.get("severity", "info")
            color  = SEVERITY_COLORS.get(sev, "#888")
            mitre_badges = "".join(
                f'<span class="mitre-badge">{m["id"]}: {m["name"]}</span>'
                for m in f.get("mitre", [])
            )
            finding_cards += f"""
            <div class="finding" style="border-left:4px solid {color}">
              <div class="finding-header">
                <span class="badge" style="background:{color}">{sev.upper()}</span>
                <strong>{f.get("title","")}</strong>
                {f'<span class="cve">{f["cve"]}</span>' if f.get("cve") else ""}
                {f'<span class="cvss">CVSS {f["cvss"]}</span>' if f.get("cvss") else ""}
              </div>
              <div class="finding-body">
                {f'<p><strong>URL:</strong> <code>{f["url"]}</code></p>' if f.get("url") else ""}
                {f'<p><strong>Description:</strong> {f["description"]}</p>' if f.get("description") else ""}
                {f'<p><strong>Evidence:</strong> <code>{f["evidence"][:300]}</code></p>' if f.get("evidence") else ""}
                {f'<p><strong>Remediation:</strong> {f["recommendation"]}</p>' if f.get("recommendation") else ""}
                {f'<div class="mitre">{mitre_badges}</div>' if mitre_badges else ""}
              </div>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PhantomRecon Report — {self.target}</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background:#0a0a0a; color:#d4d4d4; margin:0; padding:20px; }}
  h1 {{ color:#00ff41; font-size:22px; border-bottom:1px solid #333; padding-bottom:8px; }}
  h2 {{ color:#ff6600; font-size:16px; margin-top:24px; }}
  .meta {{ color:#666; font-size:12px; margin-bottom:16px; }}
  table {{ border-collapse:collapse; width:300px; }}
  td,th {{ padding:6px 12px; border:1px solid #333; font-size:13px; }}
  .badge {{ padding:2px 8px; border-radius:3px; font-size:11px; color:#fff; font-weight:bold; }}
  .finding {{ background:#111; border-radius:4px; margin:12px 0; padding:12px; }}
  .finding-header {{ display:flex; align-items:center; gap:8px; margin-bottom:8px; }}
  .finding-body {{ font-size:13px; }}
  code {{ background:#1a1a1a; padding:2px 6px; border-radius:2px; font-family:monospace; word-break:break-all; }}
  .cve {{ color:#ff6600; font-size:11px; }}
  .cvss {{ color:#ffc107; font-size:11px; }}
  .mitre-badge {{ background:#1a1a2e; border:1px solid #3a3a6e; color:#7777ff; padding:2px 6px; border-radius:2px; font-size:10px; margin:2px; display:inline-block; }}
</style>
</head>
<body>
<h1>PhantomRecon Security Report</h1>
<div class="meta">Target: <strong>{self.target}</strong> &nbsp;|&nbsp; Scan: {self.scan_start[:19]} → {self.scan_end[:19]} &nbsp;|&nbsp; Generated: {datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")} UTC</div>

<h2>Executive Summary</h2>
<table>{summary_rows}</table>
<p style="color:#888;font-size:12px;">Total: {len(self.findings)} findings</p>

<h2>Technical Findings</h2>
{finding_cards}
</body></html>"""

        if output_path:
            with open(output_path, "w") as fh:
                fh.write(html)
        return html


# ---------------------------------------------------------------------------
# Master Threat Intel Aggregator
# ---------------------------------------------------------------------------

class ThreatIntelAggregator:
    def __init__(self, vt_key: Optional[str] = None,
                 abuse_key: Optional[str] = None,
                 shodan_key: Optional[str] = None):
        self.vt     = VirusTotalEnricher(vt_key)     if vt_key     else None
        self.abuse  = AbuseIPDB(abuse_key)            if abuse_key  else None
        self.shodan = ShodanEnricher(shodan_key)      if shodan_key else None

    def enrich_ip(self, ip: str) -> Dict:
        result: Dict = {"ip": ip}
        if self.vt:
            result["virustotal"] = self.vt.lookup_ip(ip)
        if self.abuse:
            result["abuseipdb"]  = self.abuse.check_ip(ip)
        if self.shodan:
            result["shodan"]     = self.shodan.host_info(ip)
        return result

    def enrich_domain(self, domain: str) -> Dict:
        result: Dict = {"domain": domain}
        if self.vt:
            result["virustotal"] = self.vt.lookup_domain(domain)
        return result

    def enrich_findings(self, findings: List[Dict]) -> List[Dict]:
        enriched = []
        for f in findings:
            vtype = f.get("module", f.get("vuln_type", ""))
            f["mitre"] = tag_mitre(vtype)
            enriched.append(f)
        return enriched
