import asyncio

import httpx

from osint.username import Platform, check_username


def test_username_checker_uses_mocked_http_responses():
    platforms = [
        Platform(name="FoundSite", url="https://example.test/{username}", exists_status=(200,), missing_status=(404,)),
        Platform(name="MissingSite", url="https://missing.test/{username}", exists_status=(200,), missing_status=(404,)),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "example.test":
            return httpx.Response(200, request=request)
        return httpx.Response(404, request=request)

    transport = httpx.MockTransport(handler)

    async def run_check():
        async with httpx.AsyncClient(transport=transport) as client:
            return await check_username("alice", platforms=platforms, delay=0, client=client)

    result = asyncio.run(run_check())

    assert result["query"] == "alice"
    assert result["found_count"] == 1
    assert result["total"] == 2
    assert result["results"][0]["platform"] == "FoundSite"
    assert result["results"][0]["confidence_label"] == "high"
    assert result["results"][0]["category"] == "general"


def test_username_normalization_rejects_spaces():
    async def run_check():
        await check_username("bad name", platforms=[], delay=0)

    try:
        asyncio.run(run_check())
    except ValueError as exc:
        assert "spaces" in str(exc)
    else:
        raise AssertionError("Expected ValueError")
