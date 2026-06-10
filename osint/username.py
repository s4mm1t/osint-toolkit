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
    exists_status: tuple[int, ...] = (200,)
    missing_status: tuple[int, ...] = (404,)
    method: str = "GET"
    error_status: tuple[int, ...] = (429, 500, 502, 503, 504)
    notes: str = ""

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "Platform":
        return cls(
            name=str(data["name"]),
            url=str(data["url"]),
            exists_status=tuple(data.get("exists_status", [200])),
            missing_status=tuple(data.get("missing_status", [404])),
            method=str(data.get("method", "GET")).upper(),
            error_status=tuple(data.get("error_status", [429, 500, 502, 503, 504])),
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
    except httpx.TimeoutException:
        return {
            "platform": platform.name,
            "url": profile_url,
            "exists": None,
            "status": "timeout",
            "status_code": None,
            "notes": platform.notes,
        }
    except httpx.HTTPError as exc:
        return {
            "platform": platform.name,
            "url": profile_url,
            "exists": None,
            "status": "error",
            "status_code": None,
            "error": str(exc),
            "notes": platform.notes,
        }

    if status_code in platform.exists_status:
        exists: bool | None = True
        status = "found"
    elif status_code in platform.missing_status:
        exists = False
        status = "not_found"
    elif status_code in platform.error_status:
        exists = None
        status = "rate_limited_or_error"
    else:
        exists = None
        status = "unknown"

    return {
        "platform": platform.name,
        "url": str(response.url),
        "exists": exists,
        "status": status,
        "status_code": status_code,
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
    return {
        "query": normalized,
        "total": len(results),
        "found_count": len(found),
        "unknown_count": len(unknown),
        "results": sorted(results, key=lambda item: (item["exists"] is not True, item["platform"])),
    }

