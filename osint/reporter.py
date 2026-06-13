from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def build_report(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "osint-mini-toolkit",
        "disclaimer": "Use only for lawful, authorized, educational research.",
        "summary": _summary(payload),
        "data": payload,
    }


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def to_markdown(report: dict[str, Any]) -> str:
    data = report.get("data", {})
    lines = [
        "# OSINT Mini Toolkit Investigation Report",
        "",
        f"- Generated: `{report.get('generated_at')}`",
        f"- Tool: `{report.get('tool')}`",
        f"- Disclaimer: {report.get('disclaimer')}",
        "",
        "## Executive Summary",
        "",
    ]

    for item in report.get("summary", {}).get("highlights", []):
        lines.append(f"- {item}")
    lines.append("")

    if "username" in data:
        username = data["username"]
        lines.extend(
            [
                "## Username Check",
                "",
                f"Query: `{username.get('query')}`",
                f"Found: `{username.get('found_count')}` / `{username.get('total')}`",
                f"Needs review: `{username.get('unknown_count')}`",
                "",
                "| Platform | Category | Status | Confidence | URL |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for item in username.get("results", []):
            if item.get("exists") is not True and item.get("status") != "found":
                continue
            lines.append(
                f"| {item.get('platform')} | {item.get('category')} | {item.get('status')} | {item.get('confidence_label')} | {item.get('url')} |"
            )
        lines.append("")

    if "domain" in data:
        domain = data["domain"]
        lines.extend(["## Domain Recon", "", f"Query: `{domain.get('query')}`", "", "### DNS", ""])
        for record_type, values in domain.get("dns", {}).items():
            pretty = ", ".join(values) if values else "none"
            lines.append(f"- `{record_type}`: {pretty}")
        if domain.get("risk_notes"):
            lines.extend(["", "### Notes", ""])
            for note in domain["risk_notes"]:
                lines.append(f"- {note}")
        lines.extend(["", "### Open Ports", ""])
        open_ports = [str(item["port"]) for item in domain.get("ports", []) if item.get("open") is True]
        lines.append(", ".join(open_ports) if open_ports else "No common open ports detected.")
        lines.append("")

    if "metadata" in data:
        metadata = data["metadata"]
        lines.extend(["## Metadata", "", f"File: `{metadata.get('filename')}`", f"Risk: `{metadata.get('risk', {}).get('level', 'unknown')}`", ""])
        for note in metadata.get("risk", {}).get("notes", []):
            lines.append(f"- {note}")
        lines.extend(["", "```json", json.dumps(metadata, indent=2, ensure_ascii=False, default=str), "```", ""])

    if "web_security" in data:
        web = data["web_security"]
        lines.extend(["## Web Security Check", "", f"Target: `{web.get('target')}`", f"Risk: `{web.get('risk_level')}`", ""])
        for finding in web.get("findings", []):
            lines.append(f"- **{finding.get('severity')}** `{finding.get('kind')}`: {finding.get('message')}")
        lines.append("")

    return "\n".join(lines)


def _summary(payload: dict[str, Any]) -> dict[str, Any]:
    highlights: list[str] = []
    if username := payload.get("username"):
        highlights.append(
            f"Username `{username.get('query')}`: {username.get('found_count', 0)} confirmed profiles, "
            f"{username.get('unknown_count', 0)} manual-review results."
        )
    if domain := payload.get("domain"):
        open_ports = [item["port"] for item in domain.get("ports", []) if item.get("open") is True]
        highlights.append(f"Domain `{domain.get('query')}`: {len(open_ports)} common open ports; {len(domain.get('risk_notes', []))} risk notes.")
    if metadata := payload.get("metadata"):
        highlights.append(f"File `{metadata.get('filename')}`: metadata risk is `{metadata.get('risk', {}).get('level', 'unknown')}`.")
    if web := payload.get("web_security"):
        highlights.append(f"Web target `{web.get('target')}`: `{web.get('risk_level')}` risk, {len(web.get('findings', []))} findings.")
    return {"highlights": highlights}
