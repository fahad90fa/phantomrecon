from __future__ import annotations

import asyncio
import sys
import uuid
from typing import Any, Optional
from urllib.parse import urlparse

import click

from . import __version__
from .config import apply_profile_to_config, load_config_file, load_profile, merge_config, write_example_config, PROFILES
from .engine import ScanEngine
from .models import ScanConfig, ScanModule
from .reports.reporter import Reporter
from .state import StateManager
from .ui import TerminalUI


def validate_target(ctx: click.Context, param: click.Parameter, value: str) -> str:
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    parsed = urlparse(value)
    if not parsed.netloc:
        raise click.BadParameter(f"Invalid URL: {value}")
    return value.rstrip("/")


@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.pass_context
def cli(ctx: click.Context) -> None:
    """PhantomRecon - Advanced Web Reconnaissance & Vulnerability Assessment"""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command(name="scan", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target", callback=validate_target, is_eager=True)
@click.option("--profile", default=None,
              type=click.Choice(list(PROFILES.keys()), case_sensitive=False),
              help="Scan profile: ghost (stealthy), shadow (balanced stealth), balanced, aggressive")
@click.option("--config", "config_file", default=None, help="YAML config file path")
@click.option("-t", "--threads", default=None, type=int, help="Concurrent threads (1-1000) [default: 50]")
@click.option("--timeout", default=None, type=int, help="Request timeout in seconds [default: 10]")
@click.option("--retries", default=None, type=int, help="Request retry count [default: 2]")
@click.option("--delay-min", default=None, type=float, help="Min delay between requests (seconds) [default: 0.0]")
@click.option("--delay-max", default=None, type=float, help="Max delay between requests (seconds) [default: 0.5]")
@click.option("--rate", default=None, type=int, help="Max requests/second (0=unlimited) [default: 0]")
@click.option("-w", "--wordlist", default=None, help="Custom wordlist file path")
@click.option("--wordlist-size", default=None,
              type=click.Choice(["micro", "small", "medium", "large"], case_sensitive=False),
              help="Built-in wordlist size [default: medium]")
@click.option("-e", "--extensions", default=None, help="Extensions to fuzz (comma-separated, e.g. php,asp,html)")
@click.option("--recursive/--no-recursive", default=None, help="Enable recursive directory scanning")
@click.option("--depth", default=None, type=int, help="Max recursion depth [default: 3]")
@click.option("-p", "--proxy", multiple=True, help="Proxy URL (can specify multiple). e.g. socks5://127.0.0.1:9050")
@click.option("--rotate-proxy-every", default=None, type=int, help="Rotate proxy every N requests [default: 10]")
@click.option("-u", "--user-agent", default=None, help="Custom User-Agent string")
@click.option("--no-rotate-ua", is_flag=True, default=False, help="Disable User-Agent rotation")
@click.option("-H", "--header", multiple=True, help="Custom header (format: 'Name: Value')")
@click.option("-c", "--cookie", multiple=True, help="Cookies (format: 'name=value')")
@click.option("--auth", default=None, help="Basic auth credentials (user:password)")
@click.option("--bearer", default=None, help="Bearer token for Authorization header")
@click.option("--no-follow-redirects", is_flag=True, default=False, help="Do not follow redirects")
@click.option("--verify-ssl", is_flag=True, default=False, help="Verify SSL certificates")
@click.option("-m", "--module", multiple=True,
              type=click.Choice([m.value for m in ScanModule], case_sensitive=False),
              help="Run specific module(s) only (default: all)")
@click.option("-o", "--output-dir", default=".", show_default=True, help="Output directory for reports")
@click.option("-f", "--format", "formats", multiple=True,
              type=click.Choice(["json", "html", "csv", "xml", "markdown", "sarif"], case_sensitive=False),
              help="Output format(s) (default: json, html)")
@click.option("--include-codes", default=None, help="Only show these status codes (comma-separated)")
@click.option("--exclude-codes", default=None, help="Exclude these status codes [default: 404]")
@click.option("--min-size", default=None, type=int, help="Min response size to show (bytes)")
@click.option("--max-size", default=None, type=int, help="Max response size to show (bytes, 0=unlimited)")
@click.option("--filter", "filter_regex", default=None, help="Only show responses matching regex")
@click.option("--exclude", "exclude_regex", default=None, help="Exclude responses matching regex")
@click.option("--resume", is_flag=True, default=False, help="Resume a previous interrupted scan")
@click.option("-v", "--verbose", count=True, help="Verbosity (-v, -vv)")
@click.option("-q", "--quiet", is_flag=True, default=False, help="Quiet mode (no terminal output)")
@click.version_option(__version__, "-V", "--version")
def scan(
    target: str,
    profile: Optional[str],
    config_file: Optional[str],
    threads: Optional[int],
    timeout: Optional[int],
    retries: Optional[int],
    delay_min: Optional[float],
    delay_max: Optional[float],
    rate: Optional[int],
    wordlist: Optional[str],
    wordlist_size: Optional[str],
    extensions: Optional[str],
    recursive: Optional[bool],
    depth: Optional[int],
    proxy: tuple[str, ...],
    rotate_proxy_every: Optional[int],
    user_agent: Optional[str],
    no_rotate_ua: bool,
    header: tuple[str, ...],
    cookie: tuple[str, ...],
    auth: Optional[str],
    bearer: Optional[str],
    no_follow_redirects: bool,
    verify_ssl: bool,
    module: tuple[str, ...],
    output_dir: str,
    formats: tuple[str, ...],
    include_codes: Optional[str],
    exclude_codes: Optional[str],
    min_size: Optional[int],
    max_size: Optional[int],
    filter_regex: Optional[str],
    exclude_regex: Optional[str],
    resume: bool,
    verbose: int,
    quiet: bool,
) -> None:
    """Scan TARGET for vulnerabilities, directories, and misconfigurations.

    TARGET: URL to scan (e.g. https://target.example.com)

    \b
    Examples:
      phantomrecon scan https://target.example.com
      phantomrecon scan https://target.example.com --profile ghost
      phantomrecon scan https://target.example.com --config scan.yaml
      phantomrecon scan https://target.example.com -t 100 --wordlist-size large
      phantomrecon scan https://target.example.com -m vulns -m headers -m ssl
      phantomrecon scan https://target.example.com -p socks5://127.0.0.1:9050
      phantomrecon scan https://target.example.com -e php,asp,html --recursive
      phantomrecon scan https://target.example.com -o ./results -f html -f json -f csv
    """
    ui = TerminalUI(verbosity=verbose)

    if not quiet:
        ui.banner()

    merged: dict[str, Any] = {}

    if config_file:
        try:
            file_cfg = load_config_file(config_file)
            merged = merge_config(merged, file_cfg)
        except Exception as e:
            ui.error(f"Failed to load config file: {e}")
            sys.exit(1)

    if profile:
        try:
            profile_cfg = load_profile(profile)
            profile_cfg.pop("description", None)
            merged = merge_config(merged, profile_cfg)
        except Exception as e:
            ui.error(f"Failed to load profile: {e}")
            sys.exit(1)

    extra_headers: dict[str, str] = {}
    for h in header:
        if ":" in h:
            name, _, val = h.partition(":")
            extra_headers[name.strip()] = val.strip()

    cookies: dict[str, str] = {}
    for c in cookie:
        if "=" in c:
            name, _, val = c.partition("=")
            cookies[name.strip()] = val.strip()

    auth_tuple: Optional[tuple[str, str]] = None
    if auth:
        if ":" not in auth:
            ui.error("--auth must be in 'user:password' format")
            sys.exit(1)
        user, _, passwd = auth.partition(":")
        auth_tuple = (user, passwd)

    ext_list = [e.strip().lstrip(".") for e in extensions.split(",") if e.strip()] if extensions else (
        merged.get("extensions", [])
    )

    raw_include = include_codes or merged.get("include_codes", "")
    raw_exclude = exclude_codes or merged.get("exclude_codes", "404")
    include_code_list = [int(c.strip()) for c in str(raw_include).split(",") if c.strip().isdigit()]
    exclude_code_list = [int(c.strip()) for c in str(raw_exclude).split(",") if c.strip().isdigit()] if raw_exclude else [404]

    selected_modules: list[ScanModule] = []
    if module:
        selected_modules = [ScanModule(m) for m in module]
    elif merged.get("modules"):
        selected_modules = [ScanModule(m) for m in merged["modules"]]

    if not formats:
        formats_list: list[str] = merged.get("output_formats", ["json", "html"])
    else:
        formats_list = list(formats)

    config = ScanConfig(
        target=target,
        threads=max(1, min(threads or merged.get("threads", 50), 1000)),
        timeout=timeout or merged.get("timeout", 10),
        retries=retries or merged.get("retries", 2),
        delay_min=delay_min if delay_min is not None else merged.get("delay_min", 0.0),
        delay_max=delay_max if delay_max is not None else merged.get("delay_max", 0.5),
        rate_limit=rate if rate is not None else merged.get("rate_limit", 0),
        wordlist=wordlist or merged.get("wordlist"),
        wordlist_size=wordlist_size or merged.get("wordlist_size", "medium"),
        extensions=ext_list if isinstance(ext_list, list) else [],
        recursive=recursive if recursive is not None else merged.get("recursive", False),
        recursion_depth=depth or merged.get("recursion_depth", 3),
        proxies=list(proxy) or merged.get("proxies", []),
        rotate_proxy_every=rotate_proxy_every or merged.get("rotate_proxy_every", 10),
        user_agent=user_agent or merged.get("user_agent"),
        rotate_ua=not no_rotate_ua and merged.get("rotate_ua", True),
        headers=extra_headers or merged.get("headers", {}),
        cookies=cookies or merged.get("cookies", {}),
        auth=auth_tuple,
        auth_type="basic",
        bearer_token=bearer or merged.get("bearer"),
        follow_redirects=not no_follow_redirects and merged.get("follow_redirects", True),
        verify_ssl=verify_ssl or merged.get("verify_ssl", False),
        modules=selected_modules,
        output_dir=output_dir,
        output_formats=formats_list,
        verbosity=verbose or merged.get("verbosity", 1),
        include_codes=include_code_list,
        exclude_codes=exclude_code_list,
        min_size=min_size if min_size is not None else merged.get("min_size", 0),
        max_size=max_size if max_size is not None else merged.get("max_size", 0),
        filter_regex=filter_regex or merged.get("filter_regex"),
        exclude_regex=exclude_regex or merged.get("exclude_regex"),
    )

    state_manager = StateManager(state_dir=output_dir)
    scan_id = str(uuid.uuid4())[:8]

    if resume:
        existing_state = state_manager.find_resumable(target)
        if existing_state:
            scan_id = existing_state.scan_id
            if not quiet:
                ui.info(f"Resuming scan {scan_id} ({len(existing_state.completed_modules)} modules already done)")
        else:
            if not quiet:
                ui.warning("No resumable scan found for this target, starting fresh.")

    state = state_manager.create_state(target, scan_id)

    if not quiet:
        ui.print_config(target, config)

    def ui_callback(event: str, data: dict) -> None:
        if not quiet:
            ui.handle_event(event, data)
        if event == "module_done":
            state_manager.mark_module_done(state, data.get("module", ""))

    engine = ScanEngine(config, ui_callback=ui_callback)

    try:
        result = asyncio.run(engine.run())
    except KeyboardInterrupt:
        ui.warning("Scan interrupted by user.")
        result = engine.result
        result.end_time = __import__("time").time()

    state_manager.cleanup(state)

    if not quiet:
        ui.print_technologies(result)
        ui.print_findings_summary(result)
        ui.print_discovered_paths(result, limit=50)

    reporter = Reporter(output_dir=output_dir)
    saved = reporter.save_all(result, formats_list)

    if not quiet:
        ui.print_report_paths(saved)

    critical_high = sum(
        1 for f in result.findings
        if f.severity.value in ("critical", "high")
    )
    sys.exit(1 if critical_high > 0 else 0)


@cli.command(name="profiles", context_settings={"help_option_names": ["-h", "--help"]})
def list_profiles() -> None:
    """List available scan profiles."""
    click.echo("\nAvailable PhantomRecon Scan Profiles:\n")
    for name, data in PROFILES.items():
        click.echo(f"  [{name}]")
        click.echo(f"    {data.get('description', '')}")
        click.echo(f"    Threads: {data.get('threads')}  |  "
                   f"Delay: {data.get('delay_min')}-{data.get('delay_max')}s  |  "
                   f"Wordlist: {data.get('wordlist_size')}")
        mods = data.get("modules", [])
        click.echo(f"    Modules: {', '.join(mods) if mods else 'all'}")
        click.echo()


@cli.command(name="gen-config", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("output", default="phantomrecon.yaml")
def gen_config(output: str) -> None:
    """Generate an example YAML config file."""
    try:
        write_example_config(output)
        click.echo(f"[+] Example config written to: {output}")
    except Exception as e:
        click.echo(f"[-] Failed to write config: {e}", err=True)
        sys.exit(1)


def run() -> None:
    cli()
