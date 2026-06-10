from __future__ import annotations

import asyncio
import os
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from flask import Flask, Response, flash, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from osint.domain import recon_domain
from osint.metadata import SUPPORTED_EXTENSIONS, extract_metadata
from osint.reporter import build_report, to_json, to_markdown
from osint.username import check_username


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-change-me"),
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,
        UPLOAD_FOLDER=str(UPLOAD_DIR),
    )
    UPLOAD_DIR.mkdir(exist_ok=True)

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
        return render_template("index.html", supported_extensions=sorted(SUPPORTED_EXTENSIONS))

    @app.post("/scan")
    def scan():
        if request.form.get("authorized") != "on":
            flash("Подтверди, что проверка законная и разрешенная.", "error")
            return redirect(url_for("index"))

        username = request.form.get("username", "").strip()
        domain = request.form.get("domain", "").strip()
        include_ports = request.form.get("include_ports") == "on"
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
        return render_template(
            "index.html",
            supported_extensions=sorted(SUPPORTED_EXTENSIONS),
            report=report,
            report_json=to_json(report),
            report_markdown=to_markdown(report),
        )

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
        return render_template(
            "index.html",
            supported_extensions=sorted(SUPPORTED_EXTENSIONS),
            report=report,
            report_json=to_json(report),
            report_markdown=to_markdown(report),
        )

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

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
