from __future__ import annotations

import argparse
import asyncio

from osint.domain import recon_domain
from osint.metadata import extract_metadata
from osint.reporter import build_report, to_json, to_markdown
from osint.username import check_username


DISCLAIMER = "Use only for lawful, authorized, educational research."


def main() -> None:
    parser = argparse.ArgumentParser(description="osint-mini-toolkit CLI")
    parser.add_argument("--username", help="Username to check across public profile pages.")
    parser.add_argument("--domain", help="Domain to inspect with WHOIS, DNS, and optional port scan.")
    parser.add_argument("--metadata", help="Path to a JPEG/PNG/TIFF/DOCX file.")
    parser.add_argument("--no-ports", action="store_true", help="Skip the basic common-port scan.")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    args = parser.parse_args()

    print(f"DISCLAIMER: {DISCLAIMER}")
    payload = {}
    if args.username:
        payload["username"] = asyncio.run(check_username(args.username))
    if args.domain:
        payload["domain"] = recon_domain(args.domain, include_ports=not args.no_ports)
    if args.metadata:
        payload["metadata"] = extract_metadata(args.metadata)

    report = build_report(payload)
    print(to_markdown(report) if args.format == "markdown" else to_json(report))


if __name__ == "__main__":
    main()

