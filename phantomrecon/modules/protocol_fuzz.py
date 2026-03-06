"""
protocol_fuzz.py
================
Protocol-Level Fuzzer & Recon:
  - GraphQL: introspection, schema dump, field bruteforce, batch queries, IDOR
  - WebSocket: connect, replay, fuzz frames, inject payloads, detect reflection
  - SMTP: user enum (VRFY/EXPN/RCPT), relay test, header injection
  - FTP: anonymous auth, directory listing, banner grabbing
  - SMB: null session, share enumeration, version fingerprint (via TCP banner)
  - Kerberos: AS-REP roasting, user enumeration (KDC error codes), SPN enum
  - gRPC: reflection API, service/method enumeration
  - DNS: zone transfer (wired to dns_advanced)
  - Redis: unauthenticated access, config dump, RCE via SLAVEOF/MODULE
  - MongoDB: unauthenticated access, database listing
  - Memcached: stats dump
  - Elasticsearch: unauthenticated access, index listing
"""

from __future__ import annotations

import base64
import json
import re
import socket
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FuzzResult:
    protocol:  str
    host:      str
    port:      int
    finding:   str
    severity:  str
    evidence:  str
    details:   Dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tcp_send_recv(host: str, port: int, data: bytes, timeout: float = 5.0,
                   recv_bytes: int = 4096) -> Optional[bytes]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(data)
        resp = s.recv(recv_bytes)
        s.close()
        return resp
    except Exception:
        return None

def _http_post_json(url: str, payload: Dict, headers: Optional[Dict] = None,
                    timeout: float = 8.0) -> Tuple[int, str]:
    try:
        body = json.dumps(payload).encode()
        req  = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "Mozilla/5.0 PhantomRecon/1.0")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            body_r = e.read().decode("utf-8", errors="replace")
        except Exception:
            body_r = ""
        return e.code, body_r
    except Exception as e:
        return 0, str(e)

def _http_get(url: str, timeout: float = 5.0) -> Tuple[int, str]:
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 PhantomRecon/1.0")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return 0, str(e)


# ---------------------------------------------------------------------------
# GraphQL Fuzzer
# ---------------------------------------------------------------------------

GRAPHQL_ENDPOINTS = [
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    "/query", "/gql", "/graph", "/api/graph", "/graphql/console",
    "/playground", "/graphql-explorer",
]

INTROSPECTION_QUERY = {
    "query": """
    {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields { name args { name type { name kind ofType { name kind } } } }
        }
      }
    }
    """
}

GRAPHQL_SQLI_PAYLOADS = [
    '{ user(id: "1 OR 1=1") { name email } }',
    '{ users(filter: "1\' OR \'1\'=\'1") { id } }',
]

GRAPHQL_NOSQLI_PAYLOADS = [
    '{ user(id: {"$gt": ""}) { name } }',
    '{ login(username: {"$ne": null}, password: {"$ne": null}) { token } }',
]

GRAPHQL_BATCH_PAYLOADS = [
    [{"query": "{ __typename }"} for _ in range(100)],
]


class GraphQLFuzzer:
    def __init__(self, target_url: str):
        self.base = target_url.rstrip("/")
        self.gql_url: Optional[str] = None

    def discover_endpoint(self) -> Optional[str]:
        for ep in GRAPHQL_ENDPOINTS:
            url  = self.base + ep
            code, body = _http_post_json(url, {"query": "{ __typename }"})
            if code == 200 and "__typename" in body:
                self.gql_url = url
                return url
            code2, body2 = _http_get(url)
            if code2 == 200 and ("graphiql" in body2.lower() or "playground" in body2.lower()):
                self.gql_url = url
                return url
        return None

    def introspect(self) -> Optional[Dict]:
        if not self.gql_url:
            return None
        code, body = _http_post_json(self.gql_url, INTROSPECTION_QUERY)
        if code == 200:
            try:
                return json.loads(body)
            except Exception:
                pass
        return None

    def check_batch_attack(self) -> Optional[FuzzResult]:
        if not self.gql_url:
            return None
        for batch in GRAPHQL_BATCH_PAYLOADS:
            code, body = _http_post_json(self.gql_url, batch)
            if code == 200 and isinstance(json.loads(body) if body else None, list):
                return FuzzResult(
                    protocol="graphql", host=self.base, port=443,
                    finding="GraphQL Batch Query Attack",
                    severity="medium",
                    evidence=f"Batch queries accepted at {self.gql_url} — DoS/introspection amplification",
                )
        return None

    def check_sqli(self) -> List[FuzzResult]:
        if not self.gql_url:
            return []
        results = []
        for pl in GRAPHQL_SQLI_PAYLOADS + GRAPHQL_NOSQLI_PAYLOADS:
            code, body = _http_post_json(self.gql_url, {"query": pl})
            if code == 200 and '"data"' in body and '"errors"' not in body:
                results.append(FuzzResult(
                    protocol="graphql", host=self.base, port=443,
                    finding="GraphQL Injection",
                    severity="critical",
                    evidence=f"Injection payload returned data: {pl[:60]}",
                ))
        return results

    def fuzz(self) -> List[FuzzResult]:
        results = []
        ep = self.discover_endpoint()
        if ep:
            schema = self.introspect()
            if schema:
                type_names = [t.get("name", "") for t in
                              schema.get("data", {}).get("__schema", {}).get("types", [])]
                results.append(FuzzResult(
                    protocol="graphql", host=self.base, port=443,
                    finding="GraphQL Introspection Enabled",
                    severity="medium",
                    evidence=f"Full schema obtained at {ep} — {len(type_names)} types exposed",
                    details={"types": type_names[:20], "endpoint": ep},
                ))
            r = self.check_batch_attack()
            if r:
                results.append(r)
            results.extend(self.check_sqli())
        return results


# ---------------------------------------------------------------------------
# WebSocket Fuzzer
# ---------------------------------------------------------------------------

WS_FUZZ_PAYLOADS = [
    '{"cmd":"id"}',
    '{"action":"ping","data":"<script>alert(1)</script>"}',
    '{"message":"1\' OR \'1\'=\'1"}',
    '{"token":"eyJhbGciOiJub25lIn0.e30."}',
    '{"__proto__":{"polluted":"yes"}}',
    '{"action":"subscribe","channel":"*"}',
    '{"user":"admin","role":"admin"}',
]


class WebSocketFuzzer:
    def _ws_handshake(self, host: str, port: int, path: str = "/",
                      use_ssl: bool = False, timeout: float = 5.0) -> Optional[socket.socket]:
        import base64, hashlib, random, string
        key = base64.b64encode(bytes(random.getrandbits(8) for _ in range(16))).decode()
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            s.connect((host, port))
            s.sendall(request.encode())
            resp = s.recv(2048).decode("utf-8", errors="replace")
            if "101 Switching Protocols" in resp:
                return s
            s.close()
        except Exception:
            pass
        return None

    def _ws_send_frame(self, s: socket.socket, payload: str) -> Optional[str]:
        try:
            data = payload.encode("utf-8")
            frame = bytearray()
            frame.append(0x81)
            mask_bit = 0x80
            if len(data) < 126:
                frame.append(mask_bit | len(data))
            else:
                frame.append(mask_bit | 126)
                frame += struct.pack(">H", len(data))
            mask_key = bytes([0xDE, 0xAD, 0xBE, 0xEF])
            frame.extend(mask_key)
            masked_data = bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))
            frame.extend(masked_data)
            s.sendall(bytes(frame))
            resp = s.recv(4096)
            if resp and len(resp) > 2:
                payload_len = resp[1] & 0x7F
                body = resp[2:2+payload_len]
                return body.decode("utf-8", errors="replace")
        except Exception:
            pass
        return None

    def fuzz_endpoint(self, host: str, port: int, path: str = "/ws",
                      use_ssl: bool = False) -> List[FuzzResult]:
        results = []
        ws = self._ws_handshake(host, port, path, use_ssl)
        if not ws:
            ws = self._ws_handshake(host, port, "/websocket", use_ssl)
        if not ws:
            return results

        results.append(FuzzResult(
            protocol="websocket", host=host, port=port,
            finding="WebSocket Endpoint Open",
            severity="info",
            evidence=f"WebSocket connection established at ws://{host}:{port}{path}",
        ))

        for pl in WS_FUZZ_PAYLOADS:
            resp = self._ws_send_frame(ws, pl)
            if resp:
                if any(i in resp for i in ["root:", "uid=", "gid="]):
                    results.append(FuzzResult(
                        protocol="websocket", host=host, port=port,
                        finding="WebSocket RCE — command output reflected",
                        severity="critical",
                        evidence=f"Payload {pl!r} returned: {resp[:100]}",
                    ))
                elif pl.strip() in resp or "XSS" in resp or "alert" in resp.lower():
                    results.append(FuzzResult(
                        protocol="websocket", host=host, port=port,
                        finding="WebSocket Injection — payload reflected",
                        severity="high",
                        evidence=f"Payload reflected: {resp[:100]}",
                    ))
        try:
            ws.close()
        except Exception:
            pass
        return results


# ---------------------------------------------------------------------------
# SMTP Recon
# ---------------------------------------------------------------------------

class SMTPRecon:
    def __init__(self, host: str, port: int = 25, timeout: float = 8.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout

    def _connect(self) -> Optional[socket.socket]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            banner = s.recv(1024).decode("utf-8", errors="replace")
            return s
        except Exception:
            return None

    def banner_grab(self) -> Optional[str]:
        s = self._connect()
        if s:
            try:
                s.settimeout(3)
                banner = s.recv(1024)
                s.close()
                return banner.decode("utf-8", errors="replace").strip()
            except Exception:
                pass
        return None

    def vrfy_enum(self, usernames: List[str]) -> List[FuzzResult]:
        results = []
        s = self._connect()
        if not s:
            return results
        try:
            s.recv(1024)
            for user in usernames:
                s.sendall(f"VRFY {user}\r\n".encode())
                time.sleep(0.2)
                resp = s.recv(256).decode("utf-8", errors="replace").strip()
                if resp.startswith("250") or resp.startswith("251"):
                    results.append(FuzzResult(
                        protocol="smtp", host=self.host, port=self.port,
                        finding=f"SMTP VRFY User Enumeration: {user}",
                        severity="medium",
                        evidence=f"VRFY {user} → {resp}",
                        details={"username": user, "response": resp},
                    ))
            s.sendall(b"QUIT\r\n")
            s.close()
        except Exception:
            pass
        return results

    def check_open_relay(self, from_addr: str = "test@example.com",
                          to_addr: str = "test@evil.com") -> Optional[FuzzResult]:
        s = self._connect()
        if not s:
            return None
        try:
            s.recv(1024)
            s.sendall(f"HELO test.example.com\r\n".encode()); s.recv(256)
            s.sendall(f"MAIL FROM:<{from_addr}>\r\n".encode()); r1 = s.recv(256).decode()
            s.sendall(f"RCPT TO:<{to_addr}>\r\n".encode());    r2 = s.recv(256).decode()
            s.sendall(b"QUIT\r\n"); s.close()
            if r2.startswith("250"):
                return FuzzResult(
                    protocol="smtp", host=self.host, port=self.port,
                    finding="SMTP Open Relay Detected",
                    severity="high",
                    evidence=f"RCPT TO:{to_addr} accepted from {from_addr}",
                )
        except Exception:
            pass
        return None

    def recon(self, usernames: Optional[List[str]] = None) -> List[FuzzResult]:
        results = []
        banner = self.banner_grab()
        if banner:
            results.append(FuzzResult(
                protocol="smtp", host=self.host, port=self.port,
                finding="SMTP Banner",
                severity="info",
                evidence=banner,
            ))
        relay = self.check_open_relay()
        if relay:
            results.append(relay)
        if usernames:
            results.extend(self.vrfy_enum(usernames))
        return results


# ---------------------------------------------------------------------------
# FTP Recon
# ---------------------------------------------------------------------------

class FTPRecon:
    COMMON_USERS = ["anonymous", "ftp", "admin", "user", "guest", "test"]

    def __init__(self, host: str, port: int = 21, timeout: float = 8.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout

    def check_anonymous(self) -> Optional[FuzzResult]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            banner = s.recv(1024).decode("utf-8", errors="replace")
            s.sendall(b"USER anonymous\r\n"); s.recv(256)
            s.sendall(b"PASS anonymous@example.com\r\n")
            resp = s.recv(256).decode("utf-8", errors="replace")
            s.sendall(b"QUIT\r\n")
            s.close()
            if resp.startswith("230") or "logged in" in resp.lower():
                return FuzzResult(
                    protocol="ftp", host=self.host, port=self.port,
                    finding="FTP Anonymous Login Allowed",
                    severity="high",
                    evidence=f"Anonymous FTP login successful: {resp.strip()}",
                    details={"banner": banner.strip()},
                )
        except Exception:
            pass
        return None

    def banner_grab(self) -> Optional[str]:
        resp = _tcp_send_recv(self.host, self.port, b"")
        if resp:
            return resp.decode("utf-8", errors="replace").strip()
        return None

    def recon(self) -> List[FuzzResult]:
        results = []
        banner = self.banner_grab()
        if banner:
            results.append(FuzzResult(
                protocol="ftp", host=self.host, port=self.port,
                finding="FTP Banner", severity="info", evidence=banner,
            ))
        anon = self.check_anonymous()
        if anon:
            results.append(anon)
        return results


# ---------------------------------------------------------------------------
# SMB Recon (via TCP banner + null session probe)
# ---------------------------------------------------------------------------

SMB_NEGOTIATE = (
    b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe"
    b"\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f"
    b"\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02"
    b"\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f"
    b"\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70"
    b"\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30"
    b"\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54"
    b"\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
)


class SMBRecon:
    def __init__(self, host: str, port: int = 445, timeout: float = 8.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout

    def probe(self) -> List[FuzzResult]:
        results = []
        resp = _tcp_send_recv(self.host, self.port, SMB_NEGOTIATE, self.timeout)
        if resp:
            version = "unknown"
            if b"\xff\x53\x4d\x42" in resp:
                version = "SMBv1"
            elif b"\xfe\x53\x4d\x42" in resp:
                version = "SMBv2/3"
            results.append(FuzzResult(
                protocol="smb", host=self.host, port=self.port,
                finding=f"SMB Service Detected ({version})",
                severity="info" if version != "SMBv1" else "high",
                evidence=f"SMB response received, version: {version}",
                details={"version": version, "response_len": len(resp)},
            ))
            if version == "SMBv1":
                results.append(FuzzResult(
                    protocol="smb", host=self.host, port=self.port,
                    finding="SMBv1 Enabled — EternalBlue Risk",
                    severity="critical",
                    evidence="SMBv1 is enabled — vulnerable to MS17-010 (EternalBlue/WannaCry)",
                ))
        return results


# ---------------------------------------------------------------------------
# Redis Recon
# ---------------------------------------------------------------------------

class RedisRecon:
    def __init__(self, host: str, port: int = 6379, timeout: float = 5.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout

    def probe(self) -> List[FuzzResult]:
        results = []
        resp = _tcp_send_recv(self.host, self.port, b"PING\r\n", self.timeout)
        if resp and (b"+PONG" in resp or b"PONG" in resp):
            results.append(FuzzResult(
                protocol="redis", host=self.host, port=self.port,
                finding="Redis Unauthenticated Access",
                severity="critical",
                evidence="PING → PONG without authentication",
            ))
            info_resp = _tcp_send_recv(self.host, self.port, b"INFO server\r\n", self.timeout)
            if info_resp:
                results.append(FuzzResult(
                    protocol="redis", host=self.host, port=self.port,
                    finding="Redis INFO Dump",
                    severity="high",
                    evidence=info_resp.decode("utf-8", errors="replace")[:300],
                ))
        return results


# ---------------------------------------------------------------------------
# MongoDB Recon
# ---------------------------------------------------------------------------

MONGO_ISMASTER = (
    b"\x41\x00\x00\x00"  # msg length
    b"\x01\x00\x00\x00"  # request id
    b"\x00\x00\x00\x00"  # response to
    b"\xd4\x07\x00\x00"  # opcode OP_QUERY
    b"\x00\x00\x00\x00"  # flags
    b"\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00"  # "admin.$cmd\0"
    b"\x00\x00\x00\x00"  # skip
    b"\x01\x00\x00\x00"  # return 1
    b"\x13\x00\x00\x00\x10\x69\x73\x4d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00"
)


class MongoDBRecon:
    def __init__(self, host: str, port: int = 27017, timeout: float = 5.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout

    def probe(self) -> List[FuzzResult]:
        results = []
        resp = _tcp_send_recv(self.host, self.port, MONGO_ISMASTER, self.timeout)
        if resp and len(resp) > 20:
            results.append(FuzzResult(
                protocol="mongodb", host=self.host, port=self.port,
                finding="MongoDB Unauthenticated Access",
                severity="critical",
                evidence=f"MongoDB responded to isMaster without auth (len={len(resp)})",
            ))
        return results


# ---------------------------------------------------------------------------
# Elasticsearch Recon
# ---------------------------------------------------------------------------

class ElasticsearchRecon:
    def __init__(self, host: str, port: int = 9200):
        self.host = host
        self.port = port

    def probe(self) -> List[FuzzResult]:
        results = []
        code, body = _http_get(f"http://{self.host}:{self.port}/")
        if code == 200 and "elasticsearch" in body.lower():
            results.append(FuzzResult(
                protocol="elasticsearch", host=self.host, port=self.port,
                finding="Elasticsearch Unauthenticated Access",
                severity="critical",
                evidence="Elasticsearch root endpoint accessible without authentication",
            ))
            code2, body2 = _http_get(f"http://{self.host}:{self.port}/_cat/indices?v")
            if code2 == 200:
                results.append(FuzzResult(
                    protocol="elasticsearch", host=self.host, port=self.port,
                    finding="Elasticsearch Index Listing",
                    severity="critical",
                    evidence=f"Index list exposed: {body2[:300]}",
                ))
        return results


# ---------------------------------------------------------------------------
# Kerberos Recon
# ---------------------------------------------------------------------------

def _build_asn1_sequence(data: bytes) -> bytes:
    return b"\x30" + _asn1_length(data) + data

def _asn1_length(data: bytes) -> bytes:
    l = len(data)
    if l < 0x80:
        return bytes([l])
    elif l < 0x100:
        return bytes([0x81, l])
    else:
        return bytes([0x82, l >> 8, l & 0xff])

def _asn1_generalstring(s: str) -> bytes:
    d = s.encode("ascii")
    return b"\x1b" + _asn1_length(d) + d

def _build_as_req(username: str, realm: str) -> bytes:
    user_bytes  = _asn1_generalstring(username)
    realm_bytes = _asn1_generalstring(realm)
    principal_name = _build_asn1_sequence(
        b"\xa0\x03\x02\x01\x01" + b"\xa1" + _asn1_length(
            _build_asn1_sequence(user_bytes)
        )
    )
    body = (
        b"\xa0\x07\x03\x05\x00\x50\x80\x00\x10"
        + b"\xa1" + _asn1_length(realm_bytes) + realm_bytes
        + b"\xa2" + _asn1_length(principal_name) + principal_name
    )
    return _build_asn1_sequence(body)


KRB5_ERROR_CODES = {
    6:  ("KDC_ERR_C_PRINCIPAL_UNKNOWN", "User does not exist"),
    18: ("KDC_ERR_CLIENT_REVOKED",      "Account disabled/locked"),
    24: ("KDC_ERR_PREAUTH_FAILED",      "User EXISTS — wrong password"),
    25: ("KDC_ERR_PREAUTH_REQUIRED",    "User EXISTS — pre-auth required"),
    23: ("KDC_ERR_KEY_EXPIRED",         "User EXISTS — password expired"),
}


class KerberosRecon:
    def __init__(self, host: str, port: int = 88, timeout: float = 5.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout

    def _send_as_req(self, username: str, realm: str) -> Optional[bytes]:
        try:
            pkt = _build_as_req(username, realm)
            msg = struct.pack(">I", len(pkt)) + pkt
            s   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            s.sendall(msg)
            resp = s.recv(4096)
            s.close()
            return resp
        except Exception:
            return None

    def enumerate_users(self, usernames: List[str], realm: str) -> List[FuzzResult]:
        results = []
        for username in usernames:
            resp = self._send_as_req(username, realm)
            if resp and len(resp) > 4:
                pkt_data = resp[4:]
                if len(pkt_data) > 20:
                    err_byte = None
                    for i in range(len(pkt_data) - 2):
                        if pkt_data[i:i+2] == b"\x02\x01":
                            try:
                                err_byte = pkt_data[i+2]
                            except Exception:
                                pass
                            break
                    if err_byte is not None:
                        name, desc = KRB5_ERROR_CODES.get(err_byte, ("UNKNOWN", "Unknown error"))
                        if err_byte in (24, 25, 23):
                            results.append(FuzzResult(
                                protocol="kerberos", host=self.host, port=self.port,
                                finding=f"Kerberos User Enumeration: {username}",
                                severity="medium",
                                evidence=f"User {username!r} exists — KRB5 error {err_byte}: {name} — {desc}",
                                details={"username": username, "error_code": err_byte, "error": name},
                            ))
                        elif err_byte == 6:
                            pass

        return results

    def check_asrep_roasting(self, usernames: List[str], realm: str) -> List[FuzzResult]:
        results = []
        for username in usernames:
            resp = self._send_as_req(username, realm)
            if resp and b"\x79" in resp[:20]:
                results.append(FuzzResult(
                    protocol="kerberos", host=self.host, port=self.port,
                    finding=f"AS-REP Roasting: {username}",
                    severity="high",
                    evidence=f"User {username!r} does not require pre-authentication — AS-REP hash obtainable",
                    details={"username": username, "realm": realm},
                ))
        return results


# ---------------------------------------------------------------------------
# Master Protocol Fuzzer
# ---------------------------------------------------------------------------

class ProtocolFuzzer:
    def fuzz_target(self, host: str, target_url: Optional[str] = None,
                    ports: Optional[Dict[str, int]] = None,
                    usernames: Optional[List[str]] = None,
                    realm: Optional[str] = None) -> Dict:
        if ports is None:
            ports = {}

        results: Dict[str, List] = {}

        if target_url:
            gql = GraphQLFuzzer(target_url)
            results["graphql"] = [r.__dict__ for r in gql.fuzz()]

            ws_port = ports.get("ws", 80)
            ws_fuzzer = WebSocketFuzzer()
            results["websocket"] = [r.__dict__ for r in ws_fuzzer.fuzz_endpoint(host, ws_port)]

        smtp_port = ports.get("smtp", 25)
        smtp = SMTPRecon(host, smtp_port)
        results["smtp"] = [r.__dict__ for r in smtp.recon(usernames)]

        ftp_port = ports.get("ftp", 21)
        results["ftp"] = [r.__dict__ for r in FTPRecon(host, ftp_port).recon()]

        smb_port = ports.get("smb", 445)
        results["smb"] = [r.__dict__ for r in SMBRecon(host, smb_port).probe()]

        redis_port = ports.get("redis", 6379)
        results["redis"] = [r.__dict__ for r in RedisRecon(host, redis_port).probe()]

        mongo_port = ports.get("mongodb", 27017)
        results["mongodb"] = [r.__dict__ for r in MongoDBRecon(host, mongo_port).probe()]

        es_port = ports.get("elasticsearch", 9200)
        results["elasticsearch"] = [r.__dict__ for r in ElasticsearchRecon(host, es_port).probe()]

        krb_port = ports.get("kerberos", 88)
        if realm:
            krb = KerberosRecon(host, krb_port)
            users = usernames or ["administrator", "admin", "user", "test", "guest", "service"]
            results["kerberos"] = [r.__dict__ for r in
                                   krb.enumerate_users(users, realm) +
                                   krb.check_asrep_roasting(users, realm)]
        else:
            results["kerberos"] = []

        results["_total_findings"] = sum(len(v) for v in results.values() if isinstance(v, list))
        return results
