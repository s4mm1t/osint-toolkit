from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def build_report(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "osint-mini-toolkit",
        "disclaimer": "Use only for lawful, authorized, educational research.",
        "data": payload,
    }


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def to_markdown(report: dict[str, Any]) -> str:
    data = report.get("data", {})
    lines = [
        "# OSINT Mini Toolkit Report",
        "",
        f"- Generated: `{report.get('generated_at')}`",
        f"- Tool: `{report.get('tool')}`",
        f"- Disclaimer: {report.get('disclaimer')}",
        "",
    ]

    if "username" in data:
        username = data["username"]
        lines.extend(
            [
                "## Username Check",
                "",
                f"Query: `{username.get('query')}`",
                f"Found: `{username.get('found_count')}` / `{username.get('total')}`",
                "",
                "| Platform | Status | HTTP | URL |",
                "| --- | --- | --- | --- |",
            ]
        )
        for item in username.get("results", []):
            lines.append(
                f"| {item.get('platform')} | {item.get('status')} | {item.get('status_code')} | {item.get('url')} |"
            )
        lines.append("")

    if "domain" in data:
        domain = data["domain"]
        lines.extend(["## Domain Recon", "", f"Query: `{domain.get('query')}`", "", "### DNS", ""])
        for record_type, values in domain.get("dns", {}).items():
            pretty = ", ".join(values) if values else "none"
            lines.append(f"- `{record_type}`: {pretty}")
        lines.extend(["", "### Open Ports", ""])
        open_ports = [str(item["port"]) for item in domain.get("ports", []) if item.get("open") is True]
        lines.append(", ".join(open_ports) if open_ports else "No common open ports detected.")
        lines.append("")

    if "metadata" in data:
        metadata = data["metadata"]
        lines.extend(["## Metadata", "", "```json", json.dumps(metadata, indent=2, ensure_ascii=False, default=str), "```", ""])

    return "\n".join(lines)

