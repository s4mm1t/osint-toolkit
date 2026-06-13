import httpx

from osint.websec import scan_web_security


def test_web_security_detects_reflected_xss_canary():
    def handler(request: httpx.Request) -> httpx.Response:
        query = request.url.params.get("q", "")
        html = f"<html><head><title>Test</title></head><body>{query}<form method='post'><input name='email'></form></body></html>"
        return httpx.Response(
            200,
            request=request,
            text=html,
            headers={"content-type": "text/html", "access-control-allow-origin": "*"},
        )

    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        result = scan_web_security("https://example.com/search", params=["q"], validate_public=False, client=client)

    kinds = {finding["kind"] for finding in result["findings"]}
    assert "reflected_xss" in kinds
    assert "form_security" in kinds
    assert result["risk_level"] in {"medium", "high"}

