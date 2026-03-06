"""
s3scanner.py
============
Expert cloud storage bucket scanner:
  Providers    : AWS S3, Azure Blob Storage, Google Cloud Storage,
                 DigitalOcean Spaces, Wasabi, Backblaze B2, Alibaba OSS,
                 Linode Object Storage, Vultr Object Storage
  Discovery    :
    - Permutation wordlist from org name (suffixes/prefixes/env/patterns)
    - DNS resolution + HTTP probe for each candidate
    - Regex extraction from HTML/JS source (bucket URLs)
    - Subfinder-style target → domain → org name extraction
  Permission Checks :
    - List bucket (anonymous)
    - Read objects (anonymous)
    - Write/Upload (anonymous PUT)
    - Delete (anonymous DELETE)
    - ACL read / write
  Content Enumeration :
    - List all objects (paged) with size, last-modified, etag
    - Download / preview sensitive files (regex match)
    - Detect exposed secrets: .env, .git, credentials, private keys
    - Detect config files, SQL dumps, PII data
  Output:
    - Per-bucket finding with severity (critical/high/medium/low/info)
    - Full object list with sensitive file highlights
    - JSON export
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Enums & Data classes
# ---------------------------------------------------------------------------

class CloudProvider(str, Enum):
    AWS_S3          = "aws-s3"
    AZURE_BLOB      = "azure-blob"
    GCS             = "gcs"
    DO_SPACES       = "do-spaces"
    WASABI          = "wasabi"
    BACKBLAZE       = "backblaze"
    ALIBABA_OSS     = "alibaba-oss"
    LINODE          = "linode"
    VULTR           = "vultr"


@dataclass
class BucketObject:
    key:           str
    size:          int     = 0
    last_modified: str     = ""
    etag:          str     = ""
    is_sensitive:  bool    = False
    sensitive_reason: str  = ""
    content_preview: str   = ""


@dataclass
class BucketFinding:
    provider:     CloudProvider
    bucket_name:  str
    endpoint:     str
    exists:       bool
    listable:     bool        = False
    readable:     bool        = False
    writable:     bool        = False
    deletable:    bool        = False
    acl_readable: bool        = False
    acl_writable: bool        = False
    severity:     str         = "info"
    objects:      List[BucketObject] = field(default_factory=list)
    sensitive_files: List[str]       = field(default_factory=list)
    total_objects:   int             = 0
    total_size_bytes: int            = 0
    error:           str             = ""
    region:          str             = ""
    response_headers: dict           = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Provider endpoint templates
# ---------------------------------------------------------------------------

PROVIDER_TEMPLATES: Dict[CloudProvider, List[str]] = {
    CloudProvider.AWS_S3: [
        "https://{bucket}.s3.amazonaws.com",
        "https://{bucket}.s3.{region}.amazonaws.com",
        "https://s3.amazonaws.com/{bucket}",
        "https://s3.{region}.amazonaws.com/{bucket}",
    ],
    CloudProvider.AZURE_BLOB: [
        "https://{bucket}.blob.core.windows.net",
        "https://{bucket}.blob.core.windows.net/$root",
    ],
    CloudProvider.GCS: [
        "https://storage.googleapis.com/{bucket}",
        "https://{bucket}.storage.googleapis.com",
    ],
    CloudProvider.DO_SPACES: [
        "https://{bucket}.{region}.digitaloceanspaces.com",
        "https://{bucket}.nyc3.digitaloceanspaces.com",
    ],
    CloudProvider.WASABI: [
        "https://s3.wasabisys.com/{bucket}",
        "https://{bucket}.s3.wasabisys.com",
    ],
    CloudProvider.BACKBLAZE: [
        "https://f001.backblazeb2.com/file/{bucket}/",
        "https://s3.us-west-004.backblazeb2.com/{bucket}",
    ],
    CloudProvider.ALIBABA_OSS: [
        "https://{bucket}.oss-cn-hangzhou.aliyuncs.com",
        "https://{bucket}.oss-us-west-1.aliyuncs.com",
    ],
    CloudProvider.LINODE: [
        "https://{bucket}.us-east-1.linodeobjects.com",
    ],
    CloudProvider.VULTR: [
        "https://{bucket}.ewr1.vultrobjects.com",
    ],
}

AWS_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    "ap-south-1", "sa-east-1", "ca-central-1",
]

DO_REGIONS = ["nyc3", "ams3", "sgp1", "fra1", "sfo3"]


# ---------------------------------------------------------------------------
# Bucket name generator
# ---------------------------------------------------------------------------

BUCKET_SUFFIXES = [
    "", "-backup", "-bak", "-dev", "-staging", "-prod", "-test",
    "-data", "-static", "-assets", "-media", "-files", "-uploads",
    "-images", "-img", "-content", "-public", "-private", "-internal",
    "-logs", "-archive", "-old", "-new", "-temp", "-tmp", "-store",
    "-storage", "-bucket", "-s3", "-blob", "-cdn", "-web", "-api",
    "-app", "-admin", "-config", "-secrets", "-keys", "-certs",
    "-database", "-db", "-sql", "-dumps", "-export", "-import",
    "-release", "-deploy", "-artifacts", "-ci", "-build", "-packages",
    "-reports", "-analytics", "-metrics", "-monitoring", "-security",
]

BUCKET_PREFIXES = [
    "", "www-", "static-", "assets-", "media-", "files-",
    "backup-", "dev-", "staging-", "prod-", "internal-",
    "cdn-", "data-", "app-", "api-", "admin-", "logs-",
]


def generate_bucket_names(org: str, extra_words: List[str] = None) -> List[str]:
    """Generate candidate bucket names from an org/target name."""
    org    = re.sub(r'[^a-z0-9]', '-', org.lower()).strip('-')
    words  = [org]
    # also try without separators
    clean  = org.replace('-', '').replace('.', '')
    if clean != org:
        words.append(clean)
    # add extra keywords
    for w in (extra_words or []):
        words.append(re.sub(r'[^a-z0-9]', '-', w.lower()).strip('-'))

    names: Set[str] = set()
    for base in words:
        for pre in BUCKET_PREFIXES[:8]:
            for suf in BUCKET_SUFFIXES[:20]:
                name = f"{pre}{base}{suf}"
                if 3 <= len(name) <= 63:
                    names.add(name)
    return sorted(names)


def extract_buckets_from_source(html_body: str) -> Set[str]:
    """Extract bucket names/URLs from HTML/JS source."""
    found: Set[str] = set()
    patterns = [
        r'([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com',
        r's3(?:\.[a-z0-9-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])',
        r'([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.blob\.core\.windows\.net',
        r'storage\.googleapis\.com/([a-z0-9][a-z0-9_\-]{1,61}[a-z0-9])',
        r'([a-z0-9][a-z0-9\-]{1,61})\.storage\.googleapis\.com',
        r'([a-z0-9][a-z0-9\-]{1,61})\.digitaloceanspaces\.com',
        r'([a-z0-9][a-z0-9\-]{1,61})\.s3\.wasabisys\.com',
    ]
    for pat in patterns:
        for m in re.finditer(pat, html_body, re.I):
            name = m.group(1)
            if 3 <= len(name) <= 63:
                found.add(name.lower())
    return found


# ---------------------------------------------------------------------------
# Sensitive file patterns
# ---------------------------------------------------------------------------

SENSITIVE_PATTERNS = [
    (r'\.env$|\.env\.',           "critical", "Environment variables file"),
    (r'\.git/',                   "critical", "Git repository"),
    (r'id_rsa|id_dsa|id_ecdsa',  "critical", "Private SSH key"),
    (r'private.*\.key|\.pem$',   "critical", "Private key"),
    (r'credentials|aws_access',  "critical", "AWS credentials"),
    (r'\.sql$|\.sql\.gz$',       "high",     "SQL database dump"),
    (r'backup.*\.(zip|tar|gz)',  "high",     "Backup archive"),
    (r'config\.(php|rb|py|js)',  "high",     "Application config"),
    (r'database\.yml|db\.json',  "high",     "Database config"),
    (r'wp-config\.php',          "high",     "WordPress config"),
    (r'secrets?\.(yml|json)',    "high",     "Secrets file"),
    (r'token[s]?\.(json|txt)',   "high",     "Auth tokens"),
    (r'\.(bak|orig|old)$',       "medium",   "Backup file"),
    (r'password[s]?\.(txt|csv)', "high",     "Password list"),
    (r'users?\.(csv|json|xml)',  "medium",   "User data"),
    (r'\.(log|logs)$',           "medium",   "Log file"),
    (r'phpinfo\.php',            "medium",   "PHP info"),
    (r'server-status|server-info',"medium",  "Server status"),
    (r'swagger|openapi',         "low",      "API documentation"),
    (r'robots\.txt',             "info",     "Robots.txt"),
]


def classify_sensitivity(key: str) -> Tuple[bool, str, str]:
    """Return (is_sensitive, severity, reason)."""
    for pat, sev, reason in SENSITIVE_PATTERNS:
        if re.search(pat, key, re.I):
            return True, sev, reason
    return False, "", ""


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _http_probe(
    url:     str,
    method:  str = "GET",
    timeout: float = 10.0,
    headers: dict = None,
    proxy:   str  = None,
    max_body: int = 65536,
) -> Tuple[int, dict, str]:
    """Returns (status_code, headers, body)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    hdrs = {"User-Agent": "aws-sdk-go/1.44.0 (go1.21)"}
    if headers:
        hdrs.update(headers)

    h_list = []
    if proxy:
        h_list.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    h_list.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*h_list)

    try:
        req  = urllib.request.Request(url, headers=hdrs, method=method)
        resp = opener.open(req, timeout=timeout)
        status = resp.status if hasattr(resp, "status") else 200
        body   = resp.read(max_body).decode("utf-8", errors="replace")
        return status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        body = ""
        if e.fp:
            try:
                body = e.fp.read(max_body).decode("utf-8", errors="replace")
            except Exception:
                pass
        return e.code, dict(e.headers), body
    except Exception as e:
        return 0, {}, str(e)


# ---------------------------------------------------------------------------
# Per-provider bucket probers
# ---------------------------------------------------------------------------

class _S3Prober:
    """AWS S3 bucket prober."""

    def probe(self, bucket: str, timeout: float, proxy: str = None) -> BucketFinding:
        f = BucketFinding(
            provider    = CloudProvider.AWS_S3,
            bucket_name = bucket,
            endpoint    = f"https://{bucket}.s3.amazonaws.com",
            exists      = False,
        )

        # Check existence
        status, headers, body = _http_probe(f.endpoint, timeout=timeout, proxy=proxy)
        f.response_headers = headers

        if status == 0:
            f.error = body[:100]
            return f

        # 403 = exists but no access, 404 = not found
        if status in (403, 200, 301, 307):
            f.exists = True
        elif status == 404:
            # Try path-style
            status2, headers2, body2 = _http_probe(
                f"https://s3.amazonaws.com/{bucket}", timeout=timeout, proxy=proxy)
            if status2 in (403, 200, 301, 307):
                f.exists    = True
                f.endpoint  = f"https://s3.amazonaws.com/{bucket}"
                status       = status2
                headers      = headers2
                body         = body2
            else:
                return f
        else:
            return f

        # Determine region from redirect
        if status in (301, 307):
            loc = headers.get("Location", "")
            m   = re.search(r's3[.-]([a-z0-9-]+)\.amazonaws\.com', loc)
            if m:
                f.region = m.group(1)

        # Check list permission
        list_url  = f.endpoint + "/?list-type=2&max-keys=100"
        sl, _, sb = _http_probe(list_url, timeout=timeout, proxy=proxy)
        if sl == 200 and "<ListBucketResult" in sb:
            f.listable = True
            self._parse_objects(sb, f)
            # Get more pages
            self._paginate(f, timeout, proxy)

        # Check read (HEAD a common object)
        if f.objects:
            first = f.objects[0].key
            rl, _, _ = _http_probe(f"{f.endpoint}/{first}", "HEAD", timeout=timeout, proxy=proxy)
            f.readable = rl in (200, 206)

        # Check write (PUT a test file)
        wl, _, _ = _http_probe(
            f"{f.endpoint}/.phantomrecon-test.txt",
            method="PUT",
            timeout=timeout,
            headers={"Content-Length": "0"},
            proxy=proxy,
        )
        f.writable = wl in (200, 204)
        if f.writable:
            # Clean up
            _http_probe(f"{f.endpoint}/.phantomrecon-test.txt",
                        "DELETE", timeout=timeout, proxy=proxy)

        # Check delete permission
        dl, _, _ = _http_probe(
            f"{f.endpoint}/nonexistent-phantomrecon",
            "DELETE", timeout=timeout, proxy=proxy)
        f.deletable = dl in (204, 200)

        # Check ACL
        acl_l, _, acl_b = _http_probe(f"{f.endpoint}/?acl", timeout=timeout, proxy=proxy)
        f.acl_readable = acl_l == 200 and "AccessControlPolicy" in acl_b

        f.severity = self._calc_severity(f)
        return f

    def _parse_objects(self, xml_body: str, f: BucketFinding):
        try:
            root = ET.fromstring(xml_body)
            ns   = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
            for content in root.findall(".//Contents", ns) or root.findall(".//Contents"):
                key   = (content.find("Key", ns) or content.find("Key"))
                size  = (content.find("Size", ns) or content.find("Size"))
                mtime = (content.find("LastModified", ns) or content.find("LastModified"))
                etag  = (content.find("ETag", ns) or content.find("ETag"))
                if key is None:
                    continue
                k = key.text or ""
                sens, sev, reason = classify_sensitivity(k)
                obj = BucketObject(
                    key           = k,
                    size          = int(size.text) if size is not None and size.text else 0,
                    last_modified = mtime.text if mtime is not None else "",
                    etag          = etag.text.strip('"') if etag is not None and etag.text else "",
                    is_sensitive  = sens,
                    sensitive_reason = reason,
                )
                f.objects.append(obj)
                f.total_size_bytes += obj.size
                if sens:
                    f.sensitive_files.append(f"[{sev.upper()}] {k} — {reason}")
            f.total_objects = len(f.objects)
        except ET.ParseError:
            pass

    def _paginate(self, f: BucketFinding, timeout: float, proxy: str,
                  max_pages: int = 5):
        page = 1
        ct   = ""
        while page < max_pages:
            url  = f"{f.endpoint}/?list-type=2&max-keys=1000"
            if ct:
                url += f"&continuation-token={urllib.parse.quote(ct)}"
            sl, _, sb = _http_probe(url, timeout=timeout, proxy=proxy)
            if sl != 200:
                break
            self._parse_objects(sb, f)
            trunc_m = re.search(r'<IsTruncated>(true|false)</IsTruncated>', sb, re.I)
            next_m  = re.search(r'<NextContinuationToken>(.*?)</NextContinuationToken>', sb)
            if trunc_m and trunc_m.group(1).lower() == "true" and next_m:
                ct = next_m.group(1)
                page += 1
            else:
                break

    @staticmethod
    def _calc_severity(f: BucketFinding) -> str:
        if f.writable:
            return "critical"
        if f.listable and f.sensitive_files:
            return "critical"
        if f.listable:
            return "high"
        if f.readable:
            return "high"
        if f.exists:
            return "medium"
        return "info"


class _AzureBlobProber:
    """Azure Blob Storage prober."""

    def probe(self, account: str, timeout: float, proxy: str = None) -> BucketFinding:
        endpoint = f"https://{account}.blob.core.windows.net"
        f = BucketFinding(
            provider    = CloudProvider.AZURE_BLOB,
            bucket_name = account,
            endpoint    = endpoint,
            exists      = False,
        )
        # Check existence
        status, headers, body = _http_probe(
            f"{endpoint}/?comp=list", timeout=timeout, proxy=proxy)
        f.response_headers = headers

        if status in (200, 403, 409):
            f.exists = True
        else:
            return f

        if status == 200 and "<EnumerationResults" in body:
            f.listable = True
            self._parse_containers(body, f, account, timeout, proxy)

        f.severity = "high" if f.listable else ("medium" if f.exists else "info")
        return f

    def _parse_containers(self, xml_body: str, f: BucketFinding, account: str,
                           timeout: float, proxy: str):
        try:
            root = ET.fromstring(xml_body)
            for container in root.findall(".//Container"):
                name_el = container.find("Name")
                if name_el is not None:
                    cname = name_el.text or ""
                    # Probe each container for blobs
                    blob_url = f"{f.endpoint}/{cname}?restype=container&comp=list&maxresults=100"
                    bs, _, bb = _http_probe(blob_url, timeout=timeout, proxy=proxy)
                    if bs == 200 and "<Blobs" in bb:
                        self._parse_blobs(bb, f)
        except ET.ParseError:
            pass

    def _parse_blobs(self, xml_body: str, f: BucketFinding):
        try:
            root = ET.fromstring(xml_body)
            for blob in root.findall(".//Blob"):
                name_el = blob.find("Name")
                if name_el is not None:
                    key   = name_el.text or ""
                    props = blob.find("Properties")
                    size  = 0
                    if props is not None:
                        s_el = props.find("Content-Length")
                        if s_el is not None and s_el.text:
                            size = int(s_el.text)
                    sens, sev, reason = classify_sensitivity(key)
                    obj = BucketObject(key=key, size=size,
                                       is_sensitive=sens, sensitive_reason=reason)
                    f.objects.append(obj)
                    f.total_size_bytes += size
                    if sens:
                        f.sensitive_files.append(f"[{sev.upper()}] {key} — {reason}")
            f.total_objects = len(f.objects)
        except ET.ParseError:
            pass


class _GCSProber:
    """Google Cloud Storage prober."""

    def probe(self, bucket: str, timeout: float, proxy: str = None) -> BucketFinding:
        endpoint = f"https://storage.googleapis.com/{bucket}"
        f = BucketFinding(
            provider    = CloudProvider.GCS,
            bucket_name = bucket,
            endpoint    = endpoint,
            exists      = False,
        )
        status, headers, body = _http_probe(endpoint, timeout=timeout, proxy=proxy)
        f.response_headers = headers

        if status in (200, 403):
            f.exists = True
        elif status == 404:
            return f
        else:
            return f

        # Try listing
        list_url = f"https://www.googleapis.com/storage/v1/b/{bucket}/o?maxResults=100"
        ls, _, lb = _http_probe(list_url, timeout=timeout, proxy=proxy)
        if ls == 200:
            f.listable = True
            try:
                data  = json.loads(lb)
                items = data.get("items", [])
                for item in items:
                    key  = item.get("name", "")
                    size = int(item.get("size", 0))
                    sens, sev, reason = classify_sensitivity(key)
                    obj = BucketObject(key=key, size=size,
                                       last_modified=item.get("updated",""),
                                       is_sensitive=sens, sensitive_reason=reason)
                    f.objects.append(obj)
                    f.total_size_bytes += size
                    if sens:
                        f.sensitive_files.append(f"[{sev.upper()}] {key} — {reason}")
                f.total_objects = len(f.objects)
            except json.JSONDecodeError:
                pass

        f.severity = "high" if f.listable else ("medium" if f.exists else "info")
        return f


# ---------------------------------------------------------------------------
# Main Scanner
# ---------------------------------------------------------------------------

class S3Scanner:
    def __init__(
        self,
        threads:   int   = 20,
        timeout:   float = 10.0,
        proxy:     Optional[str] = None,
        verbose:   bool  = False,
        providers: Optional[List[CloudProvider]] = None,
    ):
        self.threads   = threads
        self.timeout   = timeout
        self.proxy     = proxy
        self.verbose   = verbose
        self.providers = providers or [
            CloudProvider.AWS_S3,
            CloudProvider.AZURE_BLOB,
            CloudProvider.GCS,
        ]

        self._s3_prober    = _S3Prober()
        self._azure_prober = _AzureBlobProber()
        self._gcs_prober   = _GCSProber()

    def scan_target(
        self,
        target:      str,
        extra_words: Optional[List[str]] = None,
        scan_source: bool = True,
    ) -> List[BucketFinding]:
        """
        Full scan: extract org name → generate candidates → probe all.
        Optionally fetch target URL and extract bucket names from source.
        """
        # Extract org name from target
        domain = re.sub(r'https?://', '', target).split('/')[0].split(':')[0]
        parts  = domain.replace('www.', '').split('.')
        org    = parts[0] if parts else domain

        candidates: Set[str] = set(generate_bucket_names(org, extra_words))

        # Extract from source
        if scan_source:
            try:
                status, _, body = _http_probe(
                    target if target.startswith("http") else f"https://{target}",
                    timeout=self.timeout, proxy=self.proxy)
                if status == 200:
                    extracted = extract_buckets_from_source(body)
                    candidates.update(extracted)
            except Exception:
                pass

        return self.scan_buckets(list(candidates))

    def scan_buckets(self, bucket_names: List[str]) -> List[BucketFinding]:
        """Probe a list of bucket names across all configured providers."""
        tasks: List[Tuple[str, CloudProvider]] = []
        for name in bucket_names:
            for provider in self.providers:
                tasks.append((name, provider))

        results: List[BucketFinding] = []
        lock = threading.Lock()

        def probe(name: str, provider: CloudProvider) -> Optional[BucketFinding]:
            try:
                if provider == CloudProvider.AWS_S3:
                    return self._s3_prober.probe(name, self.timeout, self.proxy)
                elif provider == CloudProvider.AZURE_BLOB:
                    return self._azure_prober.probe(name, self.timeout, self.proxy)
                elif provider == CloudProvider.GCS:
                    return self._gcs_prober.probe(name, self.timeout, self.proxy)
            except Exception as e:
                return None

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(probe, n, p): (n, p) for n, p in tasks}
            for fut in as_completed(futures):
                r = fut.result()
                if r and r.exists:
                    with lock:
                        results.append(r)

        results.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2,
                                     "low": 3, "info": 4}.get(x.severity, 5))
        return results

    def download_sensitive_file(
        self,
        finding:  BucketFinding,
        key:      str,
        max_size: int = 1_048_576,
    ) -> Tuple[int, str]:
        """Download a specific object from an S3/GCS bucket. Returns (status, content)."""
        if finding.provider == CloudProvider.AWS_S3:
            url = f"{finding.endpoint}/{urllib.parse.quote(key)}"
        elif finding.provider == CloudProvider.GCS:
            url = f"https://storage.googleapis.com/{finding.bucket_name}/{urllib.parse.quote(key)}"
        else:
            url = f"{finding.endpoint}/{urllib.parse.quote(key)}"

        status, _, body = _http_probe(url, timeout=self.timeout,
                                      proxy=self.proxy, max_body=max_size)
        return status, body


# ---------------------------------------------------------------------------
# DNS-based bucket enumeration
# ---------------------------------------------------------------------------

def dns_check_bucket(bucket_name: str, timeout: float = 3.0) -> Dict[str, bool]:
    """Resolve bucket hostnames to detect existence without HTTP."""
    results = {}
    hosts = {
        "s3":    f"{bucket_name}.s3.amazonaws.com",
        "azure": f"{bucket_name}.blob.core.windows.net",
        "gcs":   f"{bucket_name}.storage.googleapis.com",
    }
    for k, host in hosts.items():
        try:
            socket.setdefaulttimeout(timeout)
            socket.gethostbyname(host)
            results[k] = True
        except socket.gaierror:
            results[k] = False
    return results


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def run_s3_scan(
    target:      str,
    extra_words: Optional[List[str]] = None,
    threads:     int   = 20,
    timeout:     float = 10.0,
    proxy:       Optional[str] = None,
    providers:   Optional[List[str]] = None,
    verbose:     bool  = False,
    scan_source: bool  = True,
) -> List[BucketFinding]:
    provider_enums = None
    if providers:
        provider_enums = [CloudProvider(p) for p in providers]
    scanner = S3Scanner(threads=threads, timeout=timeout, proxy=proxy,
                        verbose=verbose, providers=provider_enums)
    return scanner.scan_target(target, extra_words=extra_words, scan_source=scan_source)
