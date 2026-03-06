from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml

from .models import ScanConfig, ScanModule


PROFILES: dict[str, dict[str, Any]] = {
    "ghost": {
        "description": "Maximum stealth - very slow, minimal footprint",
        "threads": 5,
        "delay_min": 2.0,
        "delay_max": 8.0,
        "rate_limit": 3,
        "rotate_ua": True,
        "rotate_proxy_every": 5,
        "wordlist_size": "micro",
        "recursive": False,
        "modules": ["headers", "ssl", "fingerprint", "disclosure"],
        "follow_redirects": True,
        "retries": 1,
        "timeout": 15,
    },
    "shadow": {
        "description": "Balanced stealth with moderate coverage",
        "threads": 20,
        "delay_min": 0.5,
        "delay_max": 2.0,
        "rate_limit": 15,
        "rotate_ua": True,
        "rotate_proxy_every": 10,
        "wordlist_size": "small",
        "recursive": False,
        "modules": ["headers", "ssl", "methods", "fingerprint", "disclosure", "vulns"],
        "follow_redirects": True,
        "retries": 2,
        "timeout": 10,
    },
    "balanced": {
        "description": "Standard penetration testing profile",
        "threads": 50,
        "delay_min": 0.1,
        "delay_max": 0.5,
        "rate_limit": 50,
        "rotate_ua": True,
        "rotate_proxy_every": 20,
        "wordlist_size": "medium",
        "recursive": True,
        "modules": [],
        "follow_redirects": True,
        "retries": 2,
        "timeout": 10,
    },
    "aggressive": {
        "description": "Maximum coverage - noisy, fast",
        "threads": 200,
        "delay_min": 0.0,
        "delay_max": 0.0,
        "rate_limit": 0,
        "rotate_ua": True,
        "rotate_proxy_every": 50,
        "wordlist_size": "large",
        "recursive": True,
        "modules": [],
        "follow_redirects": True,
        "retries": 3,
        "timeout": 8,
    },
}


def load_profile(profile_name: str) -> dict[str, Any]:
    if profile_name not in PROFILES:
        raise ValueError(f"Unknown profile '{profile_name}'. Available: {', '.join(PROFILES.keys())}")
    return dict(PROFILES[profile_name])


def load_config_file(path: str) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(config_path) as f:
        if config_path.suffix in (".yml", ".yaml"):
            data = yaml.safe_load(f)
        else:
            raise ValueError(f"Unsupported config format: {config_path.suffix}. Use .yaml or .yml")

    return data or {}


def merge_config(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for k, v in override.items():
        if v is not None and v != "" and v != [] and v != {}:
            result[k] = v
    return result


def apply_profile_to_config(config: ScanConfig, profile_name: str) -> ScanConfig:
    profile = load_profile(profile_name)
    modules_raw = profile.pop("modules", [])
    profile.pop("description", None)

    for k, v in profile.items():
        if hasattr(config, k):
            setattr(config, k, v)

    if modules_raw:
        config.modules = [ScanModule(m) for m in modules_raw]

    return config


EXAMPLE_CONFIG = """# PhantomRecon Configuration File
# Usage: phantomrecon https://target.example.com --config config.yaml

# Basic Settings
target: https://target.example.com
profile: balanced  # ghost | shadow | balanced | aggressive

# Performance
threads: 50
timeout: 10
retries: 2

# Delays (seconds)
delay_min: 0.1
delay_max: 0.5
rate_limit: 50  # requests/second (0=unlimited)

# Authentication
# auth: "username:password"  # Basic auth
# bearer: "your-token-here"  # Bearer token
# cookies:
#   session: "abc123"
#   csrftoken: "xyz789"

# Custom Headers
# headers:
#   X-Custom-Header: "value"
#   Authorization: "Custom scheme token"

# Proxy Settings
# proxies:
#   - socks5://127.0.0.1:9050
#   - http://proxy.example.com:8080
# rotate_proxy_every: 10

# User-Agent
rotate_ua: true
# user_agent: "Custom User-Agent String"

# Wordlists
wordlist_size: medium  # micro | small | medium | large
# wordlist: /path/to/custom/wordlist.txt
extensions: ["php", "asp", "aspx", "html", "js", "json"]

# Scanning
recursive: true
recursion_depth: 3
follow_redirects: true
verify_ssl: false

# Modules (empty = all modules)
modules: []
# modules:
#   - bruteforce
#   - headers
#   - ssl
#   - methods
#   - fingerprint
#   - disclosure
#   - vulns
#   - crawler

# Response Filters
exclude_codes: [404]
# include_codes: [200, 201, 301, 302, 401, 403]
# min_size: 0
# max_size: 0
# filter_regex: "admin|config|backup"

# Output
output_dir: ./results
output_formats: [json, html]
# output_formats: [json, html, csv, xml, markdown, sarif]

# Verbosity (0=quiet, 1=normal, 2=verbose, 3=debug)
verbosity: 1
"""


def write_example_config(path: str) -> None:
    with open(path, "w") as f:
        f.write(EXAMPLE_CONFIG)
