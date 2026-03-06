from __future__ import annotations

import time
from typing import Any

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .models import Finding, ScanResult, Severity

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold orange1",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
    Severity.INFO: "dim white",
    "critical": "bold red",
    "high": "bold orange1",
    "medium": "bold yellow",
    "low": "bold cyan",
    "info": "dim white",
}

SEVERITY_ICON = {
    Severity.CRITICAL: "[red]\u2718[/red]",
    Severity.HIGH: "[orange1]\u26a0[/orange1]",
    Severity.MEDIUM: "[yellow]\u26a0[/yellow]",
    Severity.LOW: "[cyan]\u2139[/cyan]",
    Severity.INFO: "[dim white]\u2022[/dim white]",
    "critical": "[red]\u2718[/red]",
    "high": "[orange1]\u26a0[/orange1]",
    "medium": "[yellow]\u26a0[/yellow]",
    "low": "[cyan]\u2139[/cyan]",
    "info": "[dim white]\u2022[/dim white]",
}

STATUS_STYLE = {
    2: "green",
    3: "yellow",
    4: "dim white",
    5: "red",
}


class TerminalUI:
    def __init__(self, verbosity: int = 1) -> None:
        self.console = Console()
        self.verbosity = verbosity
        self._start_time = time.time()
        self._progress: Progress | None = None
        self._live: Live | None = None
        self._module_task: Any = None

    def banner(self) -> None:
        banner_text = Text()
        banner_text.append("\n")
        banner_text.append("  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗\n", style="bold cyan")
        banner_text.append("  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║\n", style="bold cyan")
        banner_text.append("  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║\n", style="bold blue")
        banner_text.append("  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║\n", style="bold blue")
        banner_text.append("  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║\n", style="bold magenta")
        banner_text.append("  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝\n", style="bold magenta")
        banner_text.append("  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗\n", style="bold cyan")
        banner_text.append("  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║\n", style="bold cyan")
        banner_text.append("  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║\n", style="bold blue")
        banner_text.append("  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║\n", style="bold blue")
        banner_text.append("  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║\n", style="bold magenta")
        banner_text.append("  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝\n", style="bold magenta")
        banner_text.append("\n")
        banner_text.append("  Advanced Web Reconnaissance & Vulnerability Assessment\n", style="italic dim white")
        banner_text.append("  Authorized Penetration Testing Tool v1.0.0\n", style="dim")
        self.console.print(Panel(banner_text, border_style="cyan", padding=(0, 2)))

    def print_config(self, target: str, config: Any) -> None:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column("Key", style="dim cyan", width=22)
        table.add_column("Value", style="white")
        table.add_row("Target", f"[bold cyan]{target}[/bold cyan]")
        table.add_row("Threads", str(config.threads))
        table.add_row("Timeout", f"{config.timeout}s")
        table.add_row("Delay", f"{config.delay_min:.1f}–{config.delay_max:.1f}s")
        table.add_row("Wordlist Size", config.wordlist_size)
        table.add_row("Extensions", ", ".join(config.extensions) if config.extensions else "None")
        table.add_row("Proxies", str(len(config.proxies)) if config.proxies else "None")
        table.add_row("Modules", ", ".join(m.value for m in config.modules) if config.modules else "All")
        self.console.print(Panel(table, title="[bold]Scan Configuration[/bold]", border_style="blue"))

    def handle_event(self, event: str, data: dict) -> None:
        if event == "scan_start":
            self.console.print(Rule(f"[bold cyan]Starting scan: {data['target']}[/bold cyan]"))

        elif event == "initial_response":
            self.console.print(
                f"  [dim]Initial response:[/dim] "
                f"[bold green]HTTP {data['status']}[/bold green] "
                f"Server: [yellow]{data['server']}[/yellow] "
                f"Type: [dim]{data['content_type'][:40]}[/dim]"
            )

        elif event == "module_start":
            self.console.print(f"\n  [bold blue]\u25ba[/bold blue] [bold]{data['module']}[/bold]")

        elif event == "module_done":
            count = data.get("count", 0)
            extra = ""
            if "extracted_paths" in data:
                extra = f" ({data['extracted_paths']} paths extracted)"
            style = "green" if count > 0 else "dim"
            self.console.print(
                f"    [dim]\u2514\u2500[/dim] [{style}]{count} result(s){extra}[/{style}]"
            )

        elif event == "waf_detected":
            self.console.print(
                f"    [bold yellow]\u26d4 WAF Detected:[/bold yellow] [yellow]{data['waf']}[/yellow]"
            )

        elif event == "bruteforce_progress":
            if data["done"] % 500 == 0 or data["status"] not in (0, 404):
                pct = (data["done"] / data["total"] * 100) if data["total"] else 0
                status_style = STATUS_STYLE.get(data["status"] // 100, "white") if data["status"] else "dim"
                if data["status"] not in (0, 404) and self.verbosity >= 2:
                    self.console.print(
                        f"    [{status_style}]{data['status']}[/{status_style}] {data['url']}"
                    )

        elif event == "finding":
            sev = data.get("severity", "info")
            title = data.get("title", "Unknown")
            url = data.get("url", "")
            icon = SEVERITY_ICON.get(sev, "•")
            style = SEVERITY_STYLE.get(sev, "white")
            self.console.print(
                f"    {icon} [{style}]{sev.upper()}[/{style}] {title}"
            )
            if self.verbosity >= 2:
                self.console.print(f"       [dim]{url}[/dim]")

        elif event == "error":
            self.console.print(f"  [red]\u2718 Error:[/red] {data['msg']}")

        elif event == "scan_complete":
            self.console.print(
                f"\n  [bold green]\u2714 Scan complete[/bold green] "
                f"in [bold]{data['duration']:.1f}s[/bold] "
                f"\u2022 {data['requests']} requests "
                f"\u2022 {data['findings']} findings "
                f"\u2022 {data['paths']} paths"
            )

    def print_findings_summary(self, result: ScanResult) -> None:
        self.console.print(Rule("[bold]Findings Summary[/bold]"))

        by_sev = result.findings_by_severity
        counts = {s.value: len(by_sev[s.value]) for s in Severity}

        stat_table = Table(box=box.ROUNDED, padding=(0, 3))
        stat_table.add_column("CRITICAL", style="bold red", justify="center")
        stat_table.add_column("HIGH", style="bold orange1", justify="center")
        stat_table.add_column("MEDIUM", style="bold yellow", justify="center")
        stat_table.add_column("LOW", style="bold cyan", justify="center")
        stat_table.add_column("INFO", style="dim white", justify="center")
        stat_table.add_row(
            str(counts["critical"]),
            str(counts["high"]),
            str(counts["medium"]),
            str(counts["low"]),
            str(counts["info"]),
        )
        self.console.print(stat_table)

        if result.findings:
            findings_table = Table(
                box=box.MINIMAL_DOUBLE_HEAD,
                show_lines=False,
                padding=(0, 1),
            )
            findings_table.add_column("Sev", width=10)
            findings_table.add_column("Title", min_width=40)
            findings_table.add_column("Module", width=14)
            findings_table.add_column("URL", max_width=60, overflow="fold")

            for sev in Severity:
                for finding in by_sev[sev.value]:
                    style = SEVERITY_STYLE[sev]
                    findings_table.add_row(
                        f"[{style}]{sev.value.upper()}[/{style}]",
                        finding.title,
                        finding.module.value,
                        f"[dim]{finding.url}[/dim]",
                    )
            self.console.print(findings_table)

    def print_discovered_paths(self, result: ScanResult, limit: int = 50) -> None:
        if not result.discovered_paths:
            return
        self.console.print(Rule("[bold]Discovered Paths[/bold]"))

        table = Table(box=box.MINIMAL_DOUBLE_HEAD, padding=(0, 1))
        table.add_column("Status", width=8, justify="center")
        table.add_column("Size", width=10, justify="right")
        table.add_column("Type", width=20)
        table.add_column("Time", width=7, justify="right")
        table.add_column("URL")

        shown = sorted(result.discovered_paths, key=lambda p: p.status_code)[:limit]
        for path in shown:
            bucket = path.status_code // 100
            style = STATUS_STYLE.get(bucket, "white")
            table.add_row(
                f"[{style}]{path.status_code}[/{style}]",
                str(path.content_length),
                path.content_type[:20] if path.content_type else "-",
                f"{path.response_time:.2f}s",
                f"[cyan]{path.url}[/cyan]",
            )

        self.console.print(table)
        if len(result.discovered_paths) > limit:
            self.console.print(f"  [dim]... and {len(result.discovered_paths) - limit} more (see report)[/dim]")

    def print_technologies(self, result: ScanResult) -> None:
        if not result.technologies:
            return
        self.console.print(Rule("[bold]Detected Technologies[/bold]"))
        tech_items = [f"[cyan]{t}[/cyan]" for t in result.technologies]
        self.console.print(Columns(tech_items, padding=(0, 2)))

    def print_report_paths(self, paths: dict[str, str]) -> None:
        self.console.print(Rule("[bold]Reports Saved[/bold]"))
        for fmt, path in paths.items():
            self.console.print(f"  [green]\u2192[/green] [bold]{fmt.upper()}:[/bold] {path}")

    def error(self, msg: str) -> None:
        self.console.print(f"[bold red]\u2718 Error:[/bold red] {msg}")

    def info(self, msg: str) -> None:
        self.console.print(f"[dim]\u2139[/dim] {msg}")

    def success(self, msg: str) -> None:
        self.console.print(f"[green]\u2714[/green] {msg}")

    def warning(self, msg: str) -> None:
        self.console.print(f"[yellow]\u26a0[/yellow] {msg}")
