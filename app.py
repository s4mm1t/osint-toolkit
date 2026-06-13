from __future__ import annotations

import asyncio
import os
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from flask import Flask, Response, flash, jsonify, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from osint.cases import CaseStore
from osint.domain import recon_domain
from osint.metadata import SUPPORTED_EXTENSIONS, extract_metadata
from osint.reporter import build_report, to_json, to_markdown
from osint.username import check_username
from osint.websec import scan_web_security


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
DATA_DIR = BASE_DIR / "data"


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-change-me"),
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,
        UPLOAD_FOLDER=str(UPLOAD_DIR),
    )
    UPLOAD_DIR.mkdir(exist_ok=True)
    store = CaseStore(DATA_DIR / "cases.json")

    @app.template_filter("host_label")
    def host_label(url: str) -> str:
        parsed = urlparse(url or "")
        host = (parsed.netloc or parsed.path).replace("www.", "")
        return host or "open link"

    @app.template_filter("status_label")
    def status_label(status: str) -> str:
        labels = {
            "found": "найдено",
            "not_found": "не найдено",
            "unknown": "проверить вручную",
            "timeout": "нет ответа",
            "error": "ошибка",
            "rate_limited_or_error": "ограничение",
        }
        return labels.get(status, status)

    @app.template_filter("nice_key")
    def nice_key(key: str) -> str:
        labels = {
            "DateTime": "Дата съемки",
            "DateTimeOriginal": "Дата оригинала",
            "Make": "Производитель",
            "Model": "Модель устройства",
            "HostComputer": "Устройство",
            "Software": "ПО",
            "GPSInfo": "GPS-данные",
            "ExifOffset": "EXIF-блок",
            "Orientation": "Ориентация",
            "XResolution": "X-разрешение",
            "YResolution": "Y-разрешение",
            "author": "Автор",
            "created": "Создан",
            "modified": "Изменен",
            "last_modified_by": "Кем изменен",
            "title": "Название",
            "subject": "Тема",
            "paragraph_count": "Абзацев",
        }
        return labels.get(key, key.replace("_", " ").title())

    @app.get("/")
    def index():
        cases = store.list_cases()
        current_case = cases[0] if cases else None
        report = build_report(current_case["runs"][-1]["payload"]) if current_case and current_case.get("runs") else None
        return render_workspace(store, report=report, current_case=current_case)

    @app.get("/cases/<case_id>")
    def case_detail(case_id: str):
        current_case = store.get_case(case_id)
        if not current_case:
            flash("Кейс не найден.", "error")
            return redirect(url_for("index"))
        report = build_report(current_case["runs"][-1]["payload"]) if current_case.get("runs") else None
        return render_workspace(store, report=report, current_case=current_case)

    @app.post("/scan")
    def scan():
        if request.form.get("authorized") != "on":
            flash("Подтверди, что проверка законная и разрешенная.", "error")
            return redirect(url_for("index"))

        username = request.form.get("username", "").strip()
        domain = request.form.get("domain", "").strip()
        include_ports = request.form.get("include_ports") == "on"
        case_title = request.form.get("case_title", "").strip()
        payload = {}

        try:
            if username:
                payload["username"] = asyncio.run(check_username(username))
            if domain:
                payload["domain"] = recon_domain(domain, include_ports=include_ports)
            if not payload:
                flash("Введи ник, домен или загрузи файл для метаданных.", "error")
                return redirect(url_for("index"))
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index"))

        report = build_report(payload)
        current_case = store.create_case(
            case_title or _case_title(payload),
            payload,
            tags=_case_tags(payload),
        )
        return render_workspace(store, report=report, current_case=current_case)

    @app.post("/metadata")
    def metadata():
        if request.form.get("authorized") != "on":
            flash("Подтверди, что у тебя есть право анализировать этот файл.", "error")
            return redirect(url_for("index"))

        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("Выбери JPEG, PNG, TIFF или DOCX-файл.", "error")
            return redirect(url_for("index"))

        filename = secure_filename(uploaded.filename)
        suffix = Path(filename).suffix.lower()
        if suffix not in SUPPORTED_EXTENSIONS:
            flash(f"Этот тип файла пока не поддерживается: {suffix}", "error")
            return redirect(url_for("index"))

        saved_path = UPLOAD_DIR / f"{uuid4().hex}_{filename}"
        uploaded.save(saved_path)
        try:
            payload = {"metadata": extract_metadata(saved_path)}
        except Exception as exc:
            flash(f"Не получилось извлечь метаданные: {exc}", "error")
            return redirect(url_for("index"))
        finally:
            saved_path.unlink(missing_ok=True)

        report = build_report(payload)
        current_case = store.create_case(f"Файл: {payload['metadata']['filename']}", payload, tags=["metadata"])
        return render_workspace(store, report=report, current_case=current_case)

    @app.post("/web-security")
    def web_security():
        if request.form.get("authorized") != "on":
            flash("Подтверди, что у тебя есть разрешение тестировать это веб-приложение.", "error")
            return redirect(url_for("index"))

        target_url = request.form.get("target_url", "").strip()
        case_title = request.form.get("case_title", "").strip()
        params = [item.strip() for item in request.form.get("params", "").split(",") if item.strip()]
        if not target_url:
            flash("Укажи публичный URL тестового или staging приложения.", "error")
            return redirect(url_for("index"))

        try:
            payload = {"web_security": scan_web_security(target_url, params=params)}
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index"))

        report = build_report(payload)
        current_case = store.create_case(
            case_title or f"Web security: {payload['web_security']['target']}",
            payload,
            tags=["web-security", "pentest"],
        )
        return render_workspace(store, report=report, current_case=current_case)

    @app.post("/watch")
    def watch():
        target_type = request.form.get("target_type", "username").strip()
        value = request.form.get("value", "").strip()
        if not value:
            flash("Укажи цель для наблюдения.", "error")
            return redirect(url_for("index"))
        store.create_watch_rule(target_type, value)
        flash("Watch rule добавлен. Сейчас это локальная заготовка под scheduled checks.", "ok")
        return redirect(url_for("index"))

    @app.post("/download/json")
    def download_json():
        content = request.form.get("content", "{}")
        return Response(
            content,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=osint-report.json"},
        )

    @app.post("/download/markdown")
    def download_markdown():
        content = request.form.get("content", "")
        return Response(
            content,
            mimetype="text/markdown",
            headers={"Content-Disposition": "attachment; filename=osint-report.md"},
        )

    @app.get("/api/cases")
    def api_cases():
        return jsonify({"cases": store.list_cases()})

    @app.get("/api/cases/<case_id>")
    def api_case(case_id: str):
        current_case = store.get_case(case_id)
        if not current_case:
            return jsonify({"error": "case not found"}), 404
        return jsonify(current_case)

    @app.post("/api/check/username")
    def api_username():
        data = request.get_json(silent=True) or {}
        username = str(data.get("username", "")).strip()
        if not username:
            return jsonify({"error": "username is required"}), 400
        result = asyncio.run(check_username(username))
        return jsonify(result)

    @app.post("/api/recon/domain")
    def api_domain():
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).strip()
        if not domain:
            return jsonify({"error": "domain is required"}), 400
        try:
            return jsonify(recon_domain(domain, include_ports=bool(data.get("include_ports", True))))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/web-security")
    def api_web_security():
        data = request.get_json(silent=True) or {}
        target_url = str(data.get("url", "")).strip()
        params = data.get("params") or []
        if not target_url:
            return jsonify({"error": "url is required"}), 400
        try:
            return jsonify(scan_web_security(target_url, params=[str(item) for item in params]))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/watch")
    def api_watch():
        return jsonify({"watch_rules": store.list_watch_rules()})

    return app


def render_workspace(
    store: CaseStore,
    report: dict | None = None,
    current_case: dict | None = None,
):
    return render_template(
        "index.html",
        supported_extensions=sorted(SUPPORTED_EXTENSIONS),
        report=report,
        current_case=current_case,
        cases=store.list_cases(),
        watch_rules=store.list_watch_rules(),
        report_json=to_json(report) if report else "",
        report_markdown=to_markdown(report) if report else "",
    )


def _case_title(payload: dict) -> str:
    parts: list[str] = []
    if username := payload.get("username"):
        parts.append(f"Ник {username.get('query')}")
    if domain := payload.get("domain"):
        parts.append(f"Домен {domain.get('query')}")
    if web := payload.get("web_security"):
        parts.append(f"Web security {web.get('target')}")
    return " + ".join(parts) or "OSINT investigation"


def _case_tags(payload: dict) -> list[str]:
    tags: list[str] = []
    if payload.get("username"):
        tags.append("username")
    if payload.get("domain"):
        tags.append("domain")
    if payload.get("metadata"):
        tags.append("metadata")
    if payload.get("web_security"):
        tags.extend(["web-security", "pentest"])
    return tags


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
