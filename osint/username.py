from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml


DEFAULT_HEADERS = {
    "User-Agent": "osint-mini-toolkit/0.1 (+educational research tool)",
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
}


@dataclass(frozen=True)
class Platform:
    name: str
    url: str
    category: str = "general"
    exists_status: tuple[int, ...] = (200,)
    missing_status: tuple[int, ...] = (404,)
    method: str = "GET"
    error_status: tuple[int, ...] = (429, 500, 502, 503, 504)
    exists_patterns: tuple[str, ...] = ()
    missing_patterns: tuple[str, ...] = ()
    notes: str = ""

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "Platform":
        return cls(
            name=str(data["name"]),
            url=str(data["url"]),
            category=str(data.get("category", "general")),
            exists_status=tuple(data.get("exists_status", [200])),
            missing_status=tuple(data.get("missing_status", [404])),
            method=str(data.get("method", "GET")).upper(),
            error_status=tuple(data.get("error_status", [429, 500, 502, 503, 504])),
            exists_patterns=tuple(data.get("exists_patterns", [])),
            missing_patterns=tuple(data.get("missing_patterns", [])),
            notes=str(data.get("notes", "")),
        )


def load_platforms(path: str | Path = "platforms.yaml") -> list[Platform]:
    with Path(path).open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or []
    return [Platform.from_mapping(item) for item in raw]


def normalize_username(username: str) -> str:
    cleaned = username.strip().lstrip("@")
    if not cleaned:
        raise ValueError("Username cannot be empty.")
    if any(char.isspace() for char in cleaned):
        raise ValueError("Username must not contain spaces.")
    return cleaned


async def check_platform(
    client: httpx.AsyncClient,
    platform: Platform,
    username: str,
    timeout: float = 8.0,
) -> dict[str, Any]:
    profile_url = platform.url.format(username=username)
    try:
        response = await client.request(
            platform.method,
            profile_url,
            follow_redirects=True,
            timeout=timeout,
        )
        status_code = response.status_code
        body = response.text[:200_000] if _needs_body(platform) else ""
    except httpx.TimeoutException:
        return {
            "platform": platform.name,
            "category": platform.category,
            "url": profile_url,
            "exists": None,
            "status": "timeout",
            "status_code": None,
            "confidence": 0.2,
            "confidence_label": "low",
            "evidence": {"method": platform.method, "final_url": profile_url},
            "notes": platform.notes,
        }
    except httpx.HTTPError as exc:
        return {
            "platform": platform.name,
            "category": platform.category,
            "url": profile_url,
            "exists": None,
            "status": "error",
            "status_code": None,
            "confidence": 0.2,
            "confidence_label": "low",
            "evidence": {"method": platform.method, "final_url": profile_url},
            "error": str(exc),
            "notes": platform.notes,
        }

    body_lower = body.lower()
    missing_pattern_hit = any(pattern.lower() in body_lower for pattern in platform.missing_patterns)
    exists_pattern_hit = any(pattern.lower() in body_lower for pattern in platform.exists_patterns)

    if status_code in platform.exists_status and not missing_pattern_hit:
        exists: bool | None = True
        status = "found"
        confidence = 0.92 if not platform.exists_patterns or exists_pattern_hit else 0.72
        confidence_label = "high" if confidence >= 0.85 else "medium"
    elif status_code in platform.missing_status:
        exists = False
        status = "not_found"
        confidence = 0.9
        confidence_label = "high"
    elif missing_pattern_hit:
        exists = False
        status = "not_found"
        confidence = 0.82
        confidence_label = "medium"
    elif status_code in platform.error_status:
        exists = None
        status = "rate_limited_or_error"
        confidence = 0.35
        confidence_label = "low"
    else:
        exists = None
        status = "unknown"
        confidence = 0.45
        confidence_label = "low"

    return {
        "platform": platform.name,
        "category": platform.category,
        "url": str(response.url),
        "exists": exists,
        "status": status,
        "status_code": status_code,
        "confidence": confidence,
        "confidence_label": confidence_label,
        "evidence": {
            "method": platform.method,
            "final_url": str(response.url),
            "matched_exists_pattern": exists_pattern_hit,
            "matched_missing_pattern": missing_pattern_hit,
        },
        "notes": platform.notes,
    }


async def check_username(
    username: str,
    platforms: list[Platform] | None = None,
    concurrency: int = 5,
    delay: float = 0.25,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    normalized = normalize_username(username)
    selected_platforms = platforms or load_platforms()
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def guarded_check(index: int, platform: Platform) -> dict[str, Any]:
        if delay > 0:
            await asyncio.sleep(index * delay)
        async with semaphore:
            assert active_client is not None
            return await check_platform(active_client, platform, normalized)

    if client is None:
        async with httpx.AsyncClient(headers=DEFAULT_HEADERS) as active_client:
            results = await asyncio.gather(
                *(guarded_check(index, platform) for index, platform in enumerate(selected_platforms))
            )
    else:
        active_client = client
        results = await asyncio.gather(
            *(guarded_check(index, platform) for index, platform in enumerate(selected_platforms))
        )

    found = [item for item in results if item["exists"] is True]
    unknown = [item for item in results if item["exists"] is None]
    categories: dict[str, int] = {}
    for item in results:
        categories[item["category"]] = categories.get(item["category"], 0) + 1
    return {
        "query": normalized,
        "total": len(results),
        "found_count": len(found),
        "unknown_count": len(unknown),
        "categories": categories,
        "results": sorted(results, key=lambda item: (item["exists"] is not True, item["platform"])),
    }


def _needs_body(platform: Platform) -> bool:
    return bool(platform.exists_patterns or platform.missing_patterns)
