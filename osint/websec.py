from __future__ import annotations

import html
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from osint.domain import SECURITY_HEADERS
from osint.targets import assert_public_url


CANARY = "osint_canary_7f3a91"
XSS_PAYLOADS = [
    CANARY,
    f"<script>window.{CANARY}=1</script>",
    f"'\"><img src=x onerror=window.{CANARY}=1>",
    f"javascript:window.{CANARY}=1",
]
DEFAULT_PARAMS = ["q", "search", "query", "s", "test", "keyword", "term", "redirect", "next", "url"]


def scan_web_security(
    target_url: str,
    params: list[str] | None = None,
    validate_public: bool = True,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    url = assert_public_url(target_url) if validate_public else target_url
    active_client = client or httpx.Client(follow_redirects=True, timeout=8.0, headers={"User-Agent": "osint-mini-toolkit/0.3"})
    close_client = client is None
    try:
        baseline = _request(active_client, "GET", url)
        cors = _check_cors(active_client, url)
        xss = _check_reflection(active_client, url, params)
    finally:
        if close_client:
            active_client.close()

    headers = baseline.get("headers", {})
    header_findings = analyze_security_headers(headers)
    cookie_findings = analyze_cookie_flags(headers.get("set-cookie", ""))
    form_findings = analyze_forms(baseline.get("body", ""))
    findings = header_findings + cookie_findings + cors["findings"] + xss["findings"] + form_findings

    return {
        "target": url,
        "status_code": baseline.get("status_code"),
        "final_url": baseline.get("final_url"),
        "title": _extract_title(baseline.get("body", "")),
        "checks": {
            "security_headers": header_findings,
            "cookies": cookie_findings,
            "cors": cors,
            "xss_reflection": xss,
            "forms": form_findings,
        },
        "findings": findings,
        "risk_score": min(sum(item["score"] for item in findings), 100),
        "risk_level": _risk_level(sum(item["score"] for item in findings)),
    }


def analyze_security_headers(headers: dict[str, str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lowered = {key.lower(): value for key, value in headers.items()}
    for header in SECURITY_HEADERS:
        if not lowered.get(header):
            findings.append(_finding("missing_header", "medium", 8, f"Missing security header: {header}", header))
    csp = lowered.get("content-security-policy", "")
    if csp and ("unsafe-inline" in csp or "*" in csp):
        findings.append(_finding("weak_csp", "medium", 12, "CSP exists but looks permissive.", "content-security-policy"))
    return findings


def analyze_cookie_flags(set_cookie: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not set_cookie:
        return findings
    for cookie in re.split(r", (?=[^;,\s]+=)", set_cookie):
        cookie_name = cookie.split("=", 1)[0]
        lower = cookie.lower()
        if "httponly" not in lower:
            findings.append(_finding("cookie_flag", "medium", 8, f"Cookie `{cookie_name}` misses HttpOnly.", cookie_name))
        if "secure" not in lower:
            findings.append(_finding("cookie_flag", "medium", 8, f"Cookie `{cookie_name}` misses Secure.", cookie_name))
        if "samesite" not in lower:
            findings.append(_finding("cookie_flag", "low", 4, f"Cookie `{cookie_name}` misses SameSite.", cookie_name))
    return findings


def analyze_forms(body: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for index, form in enumerate(re.findall(r"<form\b.*?</form>", body, flags=re.IGNORECASE | re.DOTALL), start=1):
        method_match = re.search(r"method=[\"']?([^\"'\s>]+)", form, flags=re.IGNORECASE)
        method = method_match.group(1).lower() if method_match else "get"
        has_password = bool(re.search(r"type=[\"']?password", form, flags=re.IGNORECASE))
        has_csrf = bool(re.search(r"name=[\"']?([^\"'>]*(csrf|token)[^\"'>]*)", form, flags=re.IGNORECASE))
        if method == "get" and has_password:
            findings.append(_finding("form_security", "high", 18, f"Form #{index} sends password-like fields with GET.", f"form-{index}"))
        if method == "post" and not has_csrf:
            findings.append(_finding("form_security", "medium", 10, f"Form #{index} is POST but no CSRF/token field was detected.", f"form-{index}"))
    return findings


def _check_cors(client: httpx.Client, url: str) -> dict[str, Any]:
    response = client.get(url, headers={"Origin": "https://osint-mini-toolkit.invalid"})
    headers = {key.lower(): value for key, value in response.headers.items()}
    allow_origin = headers.get("access-control-allow-origin")
    allow_credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
    findings: list[dict[str, Any]] = []
    if allow_origin == "*" and allow_credentials:
        findings.append(_finding("cors", "high", 20, "CORS allows `*` together with credentials.", "access-control"))
    elif allow_origin in {"*", "https://osint-mini-toolkit.invalid"}:
        findings.append(_finding("cors", "medium", 10, "CORS policy looks permissive or reflects arbitrary Origin.", "access-control"))
    return {"allow_origin": allow_origin, "allow_credentials": allow_credentials, "findings": findings}


def _check_reflection(client: httpx.Client, url: str, params: list[str] | None) -> dict[str, Any]:
    checked: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    parsed = urlparse(url)
    existing_params = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    selected_params = list(dict.fromkeys((params or []) + existing_params + DEFAULT_PARAMS))[:12]

    for param in selected_params:
        for payload in XSS_PAYLOADS:
            test_url = _with_query_param(url, param, payload)
            response = client.get(test_url)
            body = response.text[:200_000]
            reflected_raw = payload in body
            reflected_escaped = html.escape(payload) in body
            checked.append({"param": param, "payload": payload, "raw": reflected_raw, "escaped": reflected_escaped})
            if reflected_raw and payload != CANARY:
                severity = "high" if "<script>" in payload or "onerror=" in payload else "medium"
                findings.append(
                    _finding(
                        "reflected_xss",
                        severity,
                        22 if severity == "high" else 12,
                        f"Payload is reflected without escaping in `{param}`.",
                        param,
                    )
                )
                break
    return {"canary": CANARY, "checked_params": selected_params, "samples": checked[:30], "findings": findings}


def _request(client: httpx.Client, method: str, url: str) -> dict[str, Any]:
    response = client.request(method, url)
    return {
        "status_code": response.status_code,
        "final_url": str(response.url),
        "headers": {key.lower(): value for key, value in response.headers.items()},
        "body": response.text[:200_000],
    }


def _with_query_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[key] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


def _extract_title(html_body: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", html_body, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return " ".join(match.group(1).split())[:160]


def _finding(kind: str, severity: str, score: int, message: str, evidence: str) -> dict[str, Any]:
    return {"kind": kind, "severity": severity, "score": score, "message": message, "evidence": evidence}


def _risk_level(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 25:
        return "medium"
    return "low"
