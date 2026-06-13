from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class CaseStore:
    path: Path

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"cases": [], "watch_rules": []}
        with self.path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False, default=str)

    def list_cases(self) -> list[dict[str, Any]]:
        data = self.load()
        return sorted(data.get("cases", []), key=lambda item: item.get("updated_at", ""), reverse=True)

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        for case in self.load().get("cases", []):
            if case.get("id") == case_id:
                return case
        return None

    def create_case(
        self,
        title: str,
        payload: dict[str, Any],
        notes: str = "",
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        case = {
            "id": uuid4().hex[:12],
            "title": title or "Untitled investigation",
            "status": "open",
            "tags": tags or [],
            "notes": notes,
            "created_at": now,
            "updated_at": now,
            "runs": [],
            "evidence": [],
            "graph": {"nodes": [], "edges": []},
        }
        self.append_run(case, payload, save=False)
        data = self.load()
        data.setdefault("cases", []).append(case)
        self.save(data)
        return case

    def append_run(self, case: dict[str, Any], payload: dict[str, Any], save: bool = True) -> dict[str, Any]:
        run = {
            "id": uuid4().hex[:12],
            "created_at": _now(),
            "payload": payload,
            "summary": summarize_payload(payload),
        }
        case.setdefault("runs", []).append(run)
        case["updated_at"] = run["created_at"]
        case["evidence"] = build_evidence(payload)
        case["graph"] = build_graph(payload)
        if save:
            data = self.load()
            cases = data.setdefault("cases", [])
            for index, existing in enumerate(cases):
                if existing.get("id") == case.get("id"):
                    cases[index] = case
                    break
            self.save(data)
        return run

    def create_watch_rule(self, target_type: str, value: str, interval: str = "daily") -> dict[str, Any]:
        data = self.load()
        rule = {
            "id": uuid4().hex[:12],
            "target_type": target_type,
            "value": value,
            "interval": interval,
            "status": "active",
            "created_at": _now(),
            "last_checked_at": None,
        }
        data.setdefault("watch_rules", []).append(rule)
        self.save(data)
        return rule

    def list_watch_rules(self) -> list[dict[str, Any]]:
        return self.load().get("watch_rules", [])


def summarize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {"targets": [], "highlights": []}
    if username := payload.get("username"):
        summary["targets"].append({"type": "username", "value": username.get("query")})
        summary["highlights"].append(f"{username.get('found_count', 0)} profiles found")
    if domain := payload.get("domain"):
        summary["targets"].append({"type": "domain", "value": domain.get("query")})
        open_ports = [item["port"] for item in domain.get("ports", []) if item.get("open") is True]
        summary["highlights"].append(f"{len(open_ports)} common ports open")
    if metadata := payload.get("metadata"):
        summary["targets"].append({"type": "file", "value": metadata.get("filename")})
        summary["highlights"].append(f"metadata risk: {metadata.get('risk', {}).get('level', 'unknown')}")
    if web := payload.get("web_security"):
        summary["targets"].append({"type": "web", "value": web.get("target")})
        summary["highlights"].append(f"web security risk: {web.get('risk_level')} ({len(web.get('findings', []))} findings)")
    return summary


def build_evidence(payload: dict[str, Any]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    if username := payload.get("username"):
        for item in username.get("results", []):
            if item.get("exists") is True:
                evidence.append(
                    _evidence(
                        "profile",
                        item.get("platform"),
                        item.get("url"),
                        item.get("confidence", 0.5),
                        {
                            "status_code": item.get("status_code"),
                            "category": item.get("category"),
                            "confidence_label": item.get("confidence_label"),
                        },
                    )
                )
    if domain := payload.get("domain"):
        evidence.append(_evidence("domain", "dns", domain.get("query"), 0.9, {"records": domain.get("dns", {})}))
        if domain.get("http", {}).get("status_code"):
            evidence.append(_evidence("domain", "http", domain["http"].get("final_url"), 0.75, domain.get("http", {})))
    if metadata := payload.get("metadata"):
        evidence.append(_evidence("file", "metadata", metadata.get("filename"), 0.9, metadata.get("risk", {})))
    if web := payload.get("web_security"):
        for finding in web.get("findings", []):
            confidence = 0.82 if finding.get("severity") in {"high", "medium"} else 0.65
            evidence.append(_evidence("web", finding.get("kind"), web.get("target"), confidence, finding))
    return evidence


def build_graph(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def add_node(node_id: str, label: str, node_type: str) -> None:
        nodes[node_id] = {"id": node_id, "label": label, "type": node_type}

    def add_edge(source: str, target: str, label: str) -> None:
        edges.append({"source": source, "target": target, "label": label})

    if username := payload.get("username"):
        username_id = f"username:{username.get('query')}"
        add_node(username_id, username.get("query", "username"), "username")
        for item in username.get("results", []):
            if item.get("exists") is True:
                node_id = f"profile:{item.get('platform')}:{item.get('url')}"
                add_node(node_id, item.get("platform", "profile"), "profile")
                add_edge(username_id, node_id, item.get("confidence_label", "match"))

    if domain := payload.get("domain"):
        domain_id = f"domain:{domain.get('query')}"
        add_node(domain_id, domain.get("query", "domain"), "domain")
        for address in domain.get("dns", {}).get("A", []) + domain.get("dns", {}).get("AAAA", []):
            address_id = f"ip:{address}"
            add_node(address_id, address, "ip")
            add_edge(domain_id, address_id, "resolves")
        for port in domain.get("ports", []):
            if port.get("open") is True:
                port_id = f"port:{domain.get('query')}:{port.get('port')}"
                add_node(port_id, str(port.get("port")), "port")
                add_edge(domain_id, port_id, "open")

    if metadata := payload.get("metadata"):
        file_id = f"file:{metadata.get('filename')}"
        add_node(file_id, metadata.get("filename", "file"), "file")
        image = metadata.get("image", {})
        exif = image.get("exif", {})
        for key in ("Model", "Make", "HostComputer", "Software", "DateTime"):
            if exif.get(key):
                node_id = f"metadata:{key}:{exif[key]}"
                add_node(node_id, str(exif[key]), "metadata")
                add_edge(file_id, node_id, key)

    if web := payload.get("web_security"):
        web_id = f"web:{web.get('target')}"
        add_node(web_id, web.get("target", "web target"), "web")
        for finding in web.get("findings", [])[:20]:
            finding_id = f"finding:{finding.get('kind')}:{finding.get('evidence')}"
            add_node(finding_id, finding.get("kind", "finding"), "finding")
            add_edge(web_id, finding_id, finding.get("severity", "finding"))

    return {"nodes": list(nodes.values()), "edges": edges}


def _evidence(kind: str, source: str | None, locator: str | None, confidence: float, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": uuid4().hex[:12],
        "type": kind,
        "source": source,
        "locator": locator,
        "confidence": round(float(confidence), 2),
        "captured_at": _now(),
        "data": data,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
