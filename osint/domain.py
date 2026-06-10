from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import dns.exception
import dns.resolver


COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 8080, 8443]
DNS_RECORDS = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def normalize_domain(domain: str) -> str:
    cleaned = domain.strip().lower().replace("https://", "").replace("http://", "")
    cleaned = cleaned.split("/")[0].strip(".")
    if not cleaned or " " in cleaned:
        raise ValueError("Domain must be a valid hostname.")
    return cleaned


def lookup_whois(domain: str) -> dict[str, Any]:
    try:
        import whois

        raw = whois.whois(domain)
        return {
            "domain_name": _stringify(raw.get("domain_name")),
            "registrar": _stringify(raw.get("registrar")),
            "creation_date": _stringify(raw.get("creation_date")),
            "expiration_date": _stringify(raw.get("expiration_date")),
            "name_servers": _stringify(raw.get("name_servers")),
        }
    except Exception as exc:
        return {"error": str(exc)}


def lookup_dns(domain: str, record_types: list[str] | None = None) -> dict[str, list[str]]:
    answers: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 4

    for record_type in record_types or DNS_RECORDS:
        try:
            response = resolver.resolve(domain, record_type)
            answers[record_type] = sorted({str(item).strip('"') for item in response})
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            answers[record_type] = []
        except dns.exception.DNSException as exc:
            answers[record_type] = [f"error: {exc}"]
    return answers


def scan_port(host: str, port: int, timeout: float = 0.7) -> dict[str, Any]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        opened = sock.connect_ex((host, port)) == 0
    return {"port": port, "open": opened}


def scan_ports(host: str, ports: list[int] | None = None, timeout: float = 0.7) -> list[dict[str, Any]]:
    selected_ports = ports or COMMON_PORTS
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(12, len(selected_ports))) as executor:
        futures = {executor.submit(scan_port, host, port, timeout): port for port in selected_ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                results.append(future.result())
            except OSError as exc:
                results.append({"port": port, "open": None, "error": str(exc)})
    return sorted(results, key=lambda item: item["port"])


def recon_domain(domain: str, include_ports: bool = True) -> dict[str, Any]:
    normalized = normalize_domain(domain)
    result = {
        "query": normalized,
        "whois": lookup_whois(normalized),
        "dns": lookup_dns(normalized),
        "ports": [],
    }
    if include_ports:
        result["ports"] = scan_ports(normalized)
    return result


def _stringify(value: Any) -> Any:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        return None
    return str(value)

