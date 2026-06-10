from __future__ import annotations

from pathlib import Path
from typing import Any

from PIL import ExifTags, Image


SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".tif", ".tiff", ".png", ".docx"}


def extract_metadata(file_path: str | Path) -> dict[str, Any]:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(path)
    suffix = path.suffix.lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file type: {suffix}")

    base = {
        "filename": path.name,
        "size_bytes": path.stat().st_size,
        "extension": suffix,
    }

    if suffix in {".jpg", ".jpeg", ".tif", ".tiff", ".png"}:
        base["image"] = extract_image_metadata(path)
    elif suffix == ".docx":
        base["docx"] = extract_docx_metadata(path)
    return base


def extract_image_metadata(path: Path) -> dict[str, Any]:
    with Image.open(path) as image:
        metadata: dict[str, Any] = {
            "format": image.format,
            "mode": image.mode,
            "width": image.width,
            "height": image.height,
            "exif": {},
        }
        raw_exif = image.getexif()
        for tag_id, value in raw_exif.items():
            tag = ExifTags.TAGS.get(tag_id, str(tag_id))
            metadata["exif"][tag] = _safe_value(value)
        return metadata


def extract_docx_metadata(path: Path) -> dict[str, Any]:
    from docx import Document

    document = Document(path)
    props = document.core_properties
    return {
        "author": props.author,
        "category": props.category,
        "comments": props.comments,
        "content_status": props.content_status,
        "created": _safe_value(props.created),
        "identifier": props.identifier,
        "keywords": props.keywords,
        "language": props.language,
        "last_modified_by": props.last_modified_by,
        "last_printed": _safe_value(props.last_printed),
        "modified": _safe_value(props.modified),
        "revision": props.revision,
        "subject": props.subject,
        "title": props.title,
        "version": props.version,
        "paragraph_count": len(document.paragraphs),
    }


def _safe_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value) if not isinstance(value, (str, int, float, bool, type(None))) else value

