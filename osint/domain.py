from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import httpx

from osint.targets import assert_public_hostname, hostname_from_target


COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 8080, 8443]
DNS_RECORDS = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA"]
SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


def normalize_domain(domain: str) -> str:
    try:
        cleaned = hostname_from_target(domain)
    except ValueError as exc:
        raise ValueError("Domain must be a valid hostname.") from exc
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


def analyze_email_security(domain: str) -> dict[str, Any]:
    txt = lookup_dns(domain, ["TXT"]).get("TXT", [])
    dmarc = lookup_dns(f"_dmarc.{domain}", ["TXT"]).get("TXT", [])
    spf_records = [record for record in txt if record.lower().startswith("v=spf1")]
    dmarc_records = [record for record in dmarc if record.lower().startswith("v=dmarc1")]
    return {
        "spf": spf_records,
        "dmarc": dmarc_records,
        "has_spf": bool(spf_records),
        "has_dmarc": bool(dmarc_records),
    }


def fetch_http_intel(domain: str) -> dict[str, Any]:
    intel: dict[str, Any] = {
        "url": f"https://{domain}",
        "status_code": None,
        "final_url": None,
        "server": None,
        "powered_by": None,
        "title": None,
        "security_headers": {},
        "missing_security_headers": SECURITY_HEADERS.copy(),
        "error": None,
    }
    try:
        response = httpx.get(f"https://{domain}", follow_redirects=True, timeout=6.0, headers={"User-Agent": "osint-mini-toolkit/0.2"})
    except httpx.HTTPError as exc:
        intel["error"] = str(exc)
        return intel

    headers = {key.lower(): value for key, value in response.headers.items()}
    security = {header: headers.get(header) for header in SECURITY_HEADERS if headers.get(header)}
    intel.update(
        {
            "status_code": response.status_code,
            "final_url": str(response.url),
            "server": headers.get("server"),
            "powered_by": headers.get("x-powered-by"),
            "title": _extract_title(response.text),
            "security_headers": security,
            "missing_security_headers": [header for header in SECURITY_HEADERS if header not in security],
        }
    )
    return intel


def inspect_tls_certificate(domain: str, port: int = 443, timeout: float = 4.0) -> dict[str, Any]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as wrapped:
                cert = wrapped.getpeercert()
    except Exception as exc:
        return {"error": str(exc)}

    not_after = cert.get("notAfter")
    expires_in_days = None
    if not_after:
        try:
            expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            expires_in_days = (expires_at - datetime.now(timezone.utc)).days
        except ValueError:
            expires_in_days = None

    return {
        "subject": _cert_name(cert.get("subject", [])),
        "issuer": _cert_name(cert.get("issuer", [])),
        "not_before": cert.get("notBefore"),
        "not_after": not_after,
        "expires_in_days": expires_in_days,
        "san": [value for key, value in cert.get("subjectAltName", []) if key == "DNS"][:20],
    }


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
    normalized = assert_public_hostname(normalize_domain(domain))
    dns_data = lookup_dns(normalized)
    http_data = fetch_http_intel(normalized)
    email_security = analyze_email_security(normalized)
    tls_data = inspect_tls_certificate(normalized)
    result = {
        "query": normalized,
        "whois": lookup_whois(normalized),
        "dns": dns_data,
        "email_security": email_security,
        "http": http_data,
        "tls": tls_data,
        "ports": [],
        "risk_notes": summarize_domain_risks(dns_data, http_data, email_security, tls_data),
    }
    if include_ports:
        result["ports"] = scan_ports(normalized)
    return result


def summarize_domain_risks(
    dns_data: dict[str, list[str]],
    http_data: dict[str, Any],
    email_security: dict[str, Any],
    tls_data: dict[str, Any],
) -> list[str]:
    notes: list[str] = []
    if not email_security.get("has_spf"):
        notes.append("SPF не найден: домен может быть хуже защищен от spoofing.")
    if not email_security.get("has_dmarc"):
        notes.append("DMARC не найден: политика защиты почты не видна.")
    if http_data.get("missing_security_headers"):
        missing = ", ".join(http_data["missing_security_headers"][:3])
        notes.append(f"Не хватает security headers: {missing}.")
    if tls_data.get("expires_in_days") is not None and tls_data["expires_in_days"] < 30:
        notes.append("TLS-сертификат скоро истекает.")
    if not dns_data.get("MX"):
        notes.append("MX-записи не найдены.")
    return notes


def _extract_title(html: str) -> str | None:
    lowered = html.lower()
    start = lowered.find("<title")
    if start == -1:
        return None
    start = lowered.find(">", start)
    end = lowered.find("</title>", start)
    if start == -1 or end == -1:
        return None
    title = html[start + 1 : end].strip()
    return " ".join(title.split())[:160] if title else None


def _cert_name(parts: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    for group in parts:
        for key, value in group:
            result[key] = value
    return result


def _stringify(value: Any) -> Any:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        return None
    return str(value)
