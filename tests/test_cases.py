from osint.cases import CaseStore, build_evidence, build_graph


def test_case_store_creates_case_with_evidence_and_graph(tmp_path):
    store = CaseStore(tmp_path / "cases.json")
    payload = {
        "username": {
            "query": "alice",
            "found_count": 1,
            "unknown_count": 0,
            "total": 1,
            "results": [
                {
                    "platform": "GitHub",
                    "category": "dev",
                    "url": "https://github.com/alice",
                    "exists": True,
                    "status": "found",
                    "status_code": 200,
                    "confidence": 0.92,
                    "confidence_label": "high",
                }
            ],
        }
    }

    case = store.create_case("Alice", payload)

    assert case["title"] == "Alice"
    assert case["evidence"][0]["type"] == "profile"
    assert case["graph"]["nodes"][0]["type"] == "username"
    assert len(store.list_cases()) == 1


def test_build_graph_uses_domain_and_metadata_entities():
    payload = {
        "domain": {"query": "example.com", "dns": {"A": ["93.184.216.34"], "AAAA": []}, "ports": [{"port": 443, "open": True}]},
        "metadata": {"filename": "photo.jpg", "image": {"exif": {"Model": "Camera"}}},
    }

    graph = build_graph(payload)
    evidence = build_evidence(payload)

    assert any(node["type"] == "domain" for node in graph["nodes"])
    assert any(edge["label"] == "open" for edge in graph["edges"])
    assert any(item["type"] == "file" for item in evidence)
