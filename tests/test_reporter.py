import json

from osint.reporter import build_report, to_json, to_markdown


def test_report_json_and_markdown_export():
    report = build_report(
        {
            "username": {
                "query": "alice",
                "found_count": 1,
                "total": 1,
                "results": [{"platform": "GitHub", "status": "found", "status_code": 200, "url": "https://github.com/alice"}],
            }
        }
    )

    parsed = json.loads(to_json(report))
    markdown = to_markdown(report)

    assert parsed["tool"] == "osint-mini-toolkit"
    assert "Username Check" in markdown
    assert "GitHub" in markdown

