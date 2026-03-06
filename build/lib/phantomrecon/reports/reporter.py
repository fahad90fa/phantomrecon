from __future__ import annotations

import csv
import json
import os
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Template

from ..models import Finding, ScanResult, Severity


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc3545",
    Severity.HIGH: "#fd7e14",
    Severity.MEDIUM: "#ffc107",
    Severity.LOW: "#0dcaf0",
    Severity.INFO: "#6c757d",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhantomRecon Report - {{ result.target }}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
  .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
  header { background: linear-gradient(135deg, #161b22, #21262d); border: 1px solid #30363d; border-radius: 12px; padding: 30px; margin-bottom: 24px; }
  header h1 { font-size: 2rem; color: #58a6ff; margin-bottom: 8px; }
  header .meta { color: #8b949e; font-size: 0.9rem; }
  header .target { font-size: 1.1rem; color: #e6edf3; margin-top: 8px; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }
  .stat-card .value { font-size: 2rem; font-weight: bold; }
  .stat-card .label { color: #8b949e; font-size: 0.85rem; margin-top: 4px; }
  .stat-critical .value { color: #dc3545; }
  .stat-high .value { color: #fd7e14; }
  .stat-medium .value { color: #ffc107; }
  .stat-low .value { color: #0dcaf0; }
  .stat-info .value { color: #6c757d; }
  .stat-total .value { color: #58a6ff; }
  section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 24px; overflow: hidden; }
  section h2 { background: #21262d; padding: 16px 20px; font-size: 1.1rem; color: #e6edf3; border-bottom: 1px solid #30363d; }
  .finding { border-bottom: 1px solid #21262d; padding: 16px 20px; }
  .finding:last-child { border-bottom: none; }
  .finding-header { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 8px; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; white-space: nowrap; }
  .badge-critical { background: #dc354520; color: #dc3545; border: 1px solid #dc354540; }
  .badge-high { background: #fd7e1420; color: #fd7e14; border: 1px solid #fd7e1440; }
  .badge-medium { background: #ffc10720; color: #ffc107; border: 1px solid #ffc10740; }
  .badge-low { background: #0dcaf020; color: #0dcaf0; border: 1px solid #0dcaf040; }
  .badge-info { background: #6c757d20; color: #8b949e; border: 1px solid #6c757d40; }
  .finding-title { font-size: 1rem; color: #e6edf3; font-weight: 500; }
  .finding-url { font-size: 0.8rem; color: #58a6ff; word-break: break-all; margin-bottom: 8px; }
  .finding-desc { color: #8b949e; font-size: 0.9rem; margin-bottom: 8px; }
  .finding-evidence { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 10px; font-family: monospace; font-size: 0.8rem; color: #79c0ff; margin-bottom: 8px; white-space: pre-wrap; word-break: break-all; }
  .finding-rec { color: #3fb950; font-size: 0.85rem; padding: 8px 12px; background: #3fb95010; border-left: 3px solid #3fb950; border-radius: 0 4px 4px 0; }
  .paths-table { width: 100%; border-collapse: collapse; }
  .paths-table th { background: #21262d; padding: 10px 16px; text-align: left; font-size: 0.85rem; color: #8b949e; }
  .paths-table td { padding: 8px 16px; border-top: 1px solid #21262d; font-size: 0.85rem; }
  .paths-table tr:hover td { background: #21262d40; }
  .status-2xx { color: #3fb950; }
  .status-3xx { color: #ffc107; }
  .status-4xx { color: #8b949e; }
  .status-5xx { color: #dc3545; }
  .tech-grid { display: flex; flex-wrap: wrap; gap: 8px; padding: 16px 20px; }
  .tech-badge { background: #21262d; border: 1px solid #30363d; border-radius: 20px; padding: 4px 14px; font-size: 0.85rem; color: #79c0ff; }
  .empty { color: #6c757d; text-align: center; padding: 24px; }
  footer { text-align: center; color: #6c757d; font-size: 0.8rem; padding: 20px; }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>&#x1F4CB; PhantomRecon Report</h1>
    <div class="target">Target: <strong>{{ result.target }}</strong></div>
    <div class="meta">
      Generated: {{ generated_at }} &nbsp;|&nbsp;
      Duration: {{ "%.1f"|format(result.duration) }}s &nbsp;|&nbsp;
      Total Requests: {{ result.total_requests }} &nbsp;|&nbsp;
      Paths Discovered: {{ result.discovered_paths|length }}
    </div>
  </header>

  <div class="stats-grid">
    <div class="stat-card stat-total"><div class="value">{{ findings|length }}</div><div class="label">Total Findings</div></div>
    <div class="stat-card stat-critical"><div class="value">{{ findings|selectattr('severity.value', 'eq', 'critical')|list|length }}</div><div class="label">Critical</div></div>
    <div class="stat-card stat-high"><div class="value">{{ findings|selectattr('severity.value', 'eq', 'high')|list|length }}</div><div class="label">High</div></div>
    <div class="stat-card stat-medium"><div class="value">{{ findings|selectattr('severity.value', 'eq', 'medium')|list|length }}</div><div class="label">Medium</div></div>
    <div class="stat-card stat-low"><div class="value">{{ findings|selectattr('severity.value', 'eq', 'low')|list|length }}</div><div class="label">Low</div></div>
    <div class="stat-card stat-info"><div class="value">{{ findings|selectattr('severity.value', 'eq', 'info')|list|length }}</div><div class="label">Info</div></div>
  </div>

  {% if result.technologies %}
  <section>
    <h2>&#x1F50D; Detected Technologies</h2>
    <div class="tech-grid">
      {% for tech in result.technologies.keys() %}<span class="tech-badge">{{ tech }}</span>{% endfor %}
    </div>
  </section>
  {% endif %}

  <section>
    <h2>&#x26A0; Findings ({{ findings|length }})</h2>
    {% if findings %}
      {% for finding in findings %}
      <div class="finding">
        <div class="finding-header">
          <span class="badge badge-{{ finding.severity.value }}">{{ finding.severity.value }}</span>
          <span class="finding-title">{{ finding.title }}</span>
        </div>
        <div class="finding-url">{{ finding.url }}</div>
        <div class="finding-desc">{{ finding.description }}</div>
        {% if finding.evidence %}
        <div class="finding-evidence">{{ finding.evidence }}</div>
        {% endif %}
        {% if finding.recommendation %}
        <div class="finding-rec">&#x2714; {{ finding.recommendation }}</div>
        {% endif %}
      </div>
      {% endfor %}
    {% else %}
      <div class="empty">No findings.</div>
    {% endif %}
  </section>

  {% if result.discovered_paths %}
  <section>
    <h2>&#x1F4C1; Discovered Paths ({{ result.discovered_paths|length }})</h2>
    <table class="paths-table">
      <thead><tr><th>Status</th><th>URL</th><th>Size</th><th>Type</th><th>Time</th><th>Title</th></tr></thead>
      <tbody>
        {% for path in result.discovered_paths %}
        <tr>
          <td class="status-{{ (path.status_code // 100)|string }}xx">{{ path.status_code }}</td>
          <td><a href="{{ path.url }}" style="color:#58a6ff;text-decoration:none">{{ path.url }}</a></td>
          <td>{{ path.content_length }}</td>
          <td>{{ path.content_type[:30] if path.content_type else '-' }}</td>
          <td>{{ "%.2f"|format(path.response_time) }}s</td>
          <td>{{ path.title or '-' }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </section>
  {% endif %}

  {% if result.ssl_info %}
  <section>
    <h2>&#x1F512; SSL/TLS Information</h2>
    <div style="padding:16px 20px">
      {% for key, value in result.ssl_info.items() %}
      <div style="margin-bottom:6px"><strong style="color:#8b949e">{{ key }}:</strong> <span>{{ value }}</span></div>
      {% endfor %}
    </div>
  </section>
  {% endif %}

  <footer>PhantomRecon &mdash; Authorized Penetration Testing Tool</footer>
</div>
</body>
</html>"""


class Reporter:
    def __init__(self, output_dir: str = ".") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _base_filename(self, result: ScanResult) -> str:
        import re
        safe_target = re.sub(r"[^\w\-.]", "_", result.target.replace("://", "_"))
        timestamp = datetime.fromtimestamp(result.start_time).strftime("%Y%m%d_%H%M%S")
        return f"phantomrecon_{safe_target}_{timestamp}"

    def save_all(self, result: ScanResult, formats: list[str]) -> dict[str, str]:
        paths: dict[str, str] = {}
        base = self._base_filename(result)

        for fmt in formats:
            fmt = fmt.lower()
            if fmt == "json":
                p = self.save_json(result, base)
                paths["json"] = p
            elif fmt == "html":
                p = self.save_html(result, base)
                paths["html"] = p
            elif fmt == "csv":
                p = self.save_csv(result, base)
                paths["csv"] = p
            elif fmt == "xml":
                p = self.save_xml(result, base)
                paths["xml"] = p
            elif fmt == "markdown" or fmt == "md":
                p = self.save_markdown(result, base)
                paths["markdown"] = p
            elif fmt == "sarif":
                p = self.save_sarif(result, base)
                paths["sarif"] = p

        return paths

    def save_json(self, result: ScanResult, base: str | None = None) -> str:
        if base is None:
            base = self._base_filename(result)
        filepath = self.output_dir / f"{base}.json"

        data = {
            "target": result.target,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "duration": result.duration,
            "total_requests": result.total_requests,
            "technologies": result.technologies,
            "ssl_info": result.ssl_info,
            "headers_analysis": result.headers_analysis,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "module": f.module.value,
                    "url": f.url,
                    "description": f.description,
                    "evidence": f.evidence,
                    "recommendation": f.recommendation,
                    "cve": f.cve,
                    "cvss": f.cvss,
                    "timestamp": f.timestamp,
                }
                for f in sorted(result.findings, key=lambda x: SEVERITY_ORDER[x.severity])
            ],
            "discovered_paths": [
                {
                    "url": p.url,
                    "status_code": p.status_code,
                    "content_length": p.content_length,
                    "content_type": p.content_type,
                    "response_time": p.response_time,
                    "is_directory": p.is_directory,
                    "redirect_to": p.redirect_to,
                    "title": p.title,
                }
                for p in result.discovered_paths
            ],
            "errors": result.errors,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        return str(filepath)

    def save_html(self, result: ScanResult, base: str | None = None) -> str:
        if base is None:
            base = self._base_filename(result)
        filepath = self.output_dir / f"{base}.html"

        findings = sorted(result.findings, key=lambda x: SEVERITY_ORDER[x.severity])
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        template = Template(HTML_TEMPLATE)
        html = template.render(
            result=result,
            findings=findings,
            generated_at=generated_at,
            Severity=Severity,
        )

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        return str(filepath)

    def save_csv(self, result: ScanResult, base: str | None = None) -> str:
        if base is None:
            base = self._base_filename(result)
        filepath = self.output_dir / f"{base}.csv"

        findings = sorted(result.findings, key=lambda x: SEVERITY_ORDER[x.severity])

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "severity", "title", "url", "module", "description",
                "evidence", "recommendation", "cve", "cvss"
            ])
            writer.writeheader()
            for finding in findings:
                writer.writerow({
                    "severity": finding.severity.value,
                    "title": finding.title,
                    "url": finding.url,
                    "module": finding.module.value,
                    "description": finding.description,
                    "evidence": finding.evidence[:500] if finding.evidence else "",
                    "recommendation": finding.recommendation,
                    "cve": finding.cve or "",
                    "cvss": finding.cvss or "",
                })

        return str(filepath)

    def save_xml(self, result: ScanResult, base: str | None = None) -> str:
        if base is None:
            base = self._base_filename(result)
        filepath = self.output_dir / f"{base}.xml"

        root = ET.Element("PhantomReconReport")
        root.set("target", result.target)
        root.set("generated", datetime.now().isoformat())
        root.set("duration", f"{result.duration:.1f}")
        root.set("total_requests", str(result.total_requests))

        findings_el = ET.SubElement(root, "Findings")
        findings_el.set("count", str(len(result.findings)))

        for finding in sorted(result.findings, key=lambda x: SEVERITY_ORDER[x.severity]):
            f_el = ET.SubElement(findings_el, "Finding")
            f_el.set("severity", finding.severity.value)
            f_el.set("module", finding.module.value)
            ET.SubElement(f_el, "Title").text = finding.title
            ET.SubElement(f_el, "URL").text = finding.url
            ET.SubElement(f_el, "Description").text = finding.description
            ET.SubElement(f_el, "Evidence").text = finding.evidence or ""
            ET.SubElement(f_el, "Recommendation").text = finding.recommendation
            if finding.cve:
                ET.SubElement(f_el, "CVE").text = finding.cve

        paths_el = ET.SubElement(root, "DiscoveredPaths")
        paths_el.set("count", str(len(result.discovered_paths)))
        for path in result.discovered_paths:
            p_el = ET.SubElement(paths_el, "Path")
            p_el.set("status", str(path.status_code))
            p_el.set("size", str(path.content_length))
            p_el.text = path.url

        techs_el = ET.SubElement(root, "Technologies")
        for tech in result.technologies:
            ET.SubElement(techs_el, "Technology").text = tech

        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        tree.write(filepath, encoding="unicode", xml_declaration=True)

        return str(filepath)

    def save_markdown(self, result: ScanResult, base: str | None = None) -> str:
        if base is None:
            base = self._base_filename(result)
        filepath = self.output_dir / f"{base}.md"

        findings = sorted(result.findings, key=lambda x: SEVERITY_ORDER[x.severity])
        counts = {s: sum(1 for f in findings if f.severity == s) for s in Severity}

        severity_icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }

        lines = [
            f"# PhantomRecon Report",
            f"",
            f"**Target:** `{result.target}`  ",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Duration:** {result.duration:.1f}s  ",
            f"**Total Requests:** {result.total_requests}  ",
            f"",
            f"## Risk Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev in Severity:
            lines.append(f"| {severity_icons[sev]} {sev.value.capitalize()} | {counts[sev]} |")

        lines += [
            f"",
            f"**Risk Score:** {_calculate_risk_score(findings)}/100",
            f"",
        ]

        if result.technologies:
            lines += [
                f"## Detected Technologies",
                f"",
                f"" + ", ".join(f"`{t}`" for t in sorted(result.technologies.keys())),
                f"",
            ]

        if findings:
            lines += [f"## Findings", f""]
            for i, f in enumerate(findings, 1):
                icon = severity_icons[f.severity]
                lines += [
                    f"### {i}. {icon} {f.title}",
                    f"",
                    f"- **Severity:** {f.severity.value.upper()}",
                    f"- **URL:** `{f.url}`",
                    f"- **Module:** `{f.module.value}`",
                ]
                if f.cve:
                    lines.append(f"- **CVE:** [{f.cve}](https://nvd.nist.gov/vuln/detail/{f.cve})")
                lines += [
                    f"",
                    f"**Description:** {f.description}",
                    f"",
                ]
                if f.evidence:
                    lines += [
                        f"**Evidence:**",
                        f"```",
                        f.evidence[:500],
                        f"```",
                        f"",
                    ]
                if f.recommendation:
                    lines += [
                        f"**Recommendation:** {f.recommendation}",
                        f"",
                    ]
                lines.append(f"---")
                lines.append(f"")

        if result.discovered_paths:
            lines += [
                f"## Discovered Paths ({len(result.discovered_paths)})",
                f"",
                f"| Status | URL | Size | Type |",
                f"|--------|-----|------|------|",
            ]
            for p in result.discovered_paths[:100]:
                ct = (p.content_type[:30] if p.content_type else "-")
                lines.append(f"| {p.status_code} | `{p.url}` | {p.content_length} | {ct} |")
            if len(result.discovered_paths) > 100:
                lines.append(f"| ... | *{len(result.discovered_paths) - 100} more paths* | | |")
            lines.append(f"")

        lines += [
            f"---",
            f"*Generated by PhantomRecon — Authorized Penetration Testing Tool*",
        ]

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return str(filepath)

    def save_sarif(self, result: ScanResult, base: str | None = None) -> str:
        if base is None:
            base = self._base_filename(result)
        filepath = self.output_dir / f"{base}.sarif"

        severity_level_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }

        rules: dict[str, dict] = {}
        results_list: list[dict] = []

        for finding in result.findings:
            rule_id = finding.title.lower().replace(" ", "_").replace("/", "_")[:64]

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "helpUri": f"https://nvd.nist.gov/vuln/detail/{finding.cve}" if finding.cve else None,
                    "properties": {
                        "severity": finding.severity.value,
                        "module": finding.module.value,
                    },
                    "defaultConfiguration": {
                        "level": severity_level_map[finding.severity],
                    },
                }

            result_obj: dict = {
                "ruleId": rule_id,
                "level": severity_level_map[finding.severity],
                "message": {
                    "text": f"{finding.description}\n\nEvidence: {finding.evidence}\n\nRecommendation: {finding.recommendation}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.url,
                                "uriBaseId": "%SRCROOT%",
                            },
                        },
                    }
                ],
            }
            if finding.cve:
                result_obj["relatedLocations"] = [
                    {"message": {"text": f"CVE: {finding.cve}"}}
                ]
            results_list.append(result_obj)

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PhantomRecon",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/phantomrecon",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results_list,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "commandLine": f"phantomrecon {result.target}",
                            "startTimeUtc": datetime.fromtimestamp(result.start_time).isoformat() + "Z",
                            "endTimeUtc": datetime.fromtimestamp(result.end_time).isoformat() + "Z" if result.end_time else None,
                        }
                    ],
                }
            ],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=2, default=str)

        return str(filepath)


def _calculate_risk_score(findings: list[Finding]) -> int:
    weights = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 12,
        Severity.MEDIUM: 5,
        Severity.LOW: 2,
        Severity.INFO: 0,
    }
    score = 0
    for f in findings:
        score += weights.get(f.severity, 0)
    return min(100, score)
