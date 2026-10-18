"""Document intake: MIME sniffing, size cap and text extraction (implementation_plan §1.1, testing.md U-UPLOAD).

Only text-layer extraction (pypdf). Used for anomaly detection and to build the reader prompt; no rendering,
no script execution, no metadata display except escaped in the untrusted block.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
_PDF_MAGIC = b"%PDF-"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPG_MAGIC = b"\xff\xd8\xff"


class UploadError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def sniff_mime(data: bytes, filename: str) -> str:
    """Allow-list by content sniffing, not by extension (a renamed .exe must be rejected)."""
    if data.startswith(_PDF_MAGIC):
        return "application/pdf"
    if data.startswith(_PNG_MAGIC):
        return "image/png"
    if data.startswith(_JPG_MAGIC):
        return "image/jpeg"
    raise UploadError("UNSUPPORTED_MIME")


def validate_upload(data: bytes, filename: str) -> str:
    if len(data) == 0:
        raise UploadError("EMPTY_FILE")
    if len(data) > MAX_UPLOAD_BYTES:
        raise UploadError("TOO_LARGE")
    if ".." in filename or "/" in filename or "\\" in filename:
        raise UploadError("BAD_FILENAME")
    return sniff_mime(data, filename)


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_text(data: bytes, mime: str) -> tuple[str, dict[str, str], list[dict[str, float]]]:
    """Returns (text, metadata, spans). For images text is empty (vision model path); spans come from PDF layout."""
    if mime != "application/pdf":
        return "", {}, []
    import io

    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    meta: dict[str, str] = {}
    try:
        if reader.metadata:
            meta = {str(k).lstrip("/"): str(v) for k, v in reader.metadata.items()}
    except Exception:  # noqa: BLE001 - malformed metadata must not fail the upload
        meta = {}
    parts: list[str] = []
    spans: list[dict[str, float]] = []
    for page in reader.pages:
        try:
            parts.append(page.extract_text() or "")
        except Exception:  # noqa: BLE001
            parts.append("")
        spans.extend(_page_spans(page))
    return "\n".join(parts), meta, spans


_TF_RE = re.compile(r"/([A-Za-z0-9]+)\s+([\d.]+)\s+Tf")
_TM_RE = re.compile(r"([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+Tm")
_RG_RE = re.compile(r"([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+(rg|RG)")
_G_RE = re.compile(r"([\d.]+)\s+(g|G)(?![A-Za-z])")
_CM_RE = re.compile(r"([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+cm")


def _page_spans(page: Any) -> list[dict[str, float]]:
    """Best-effort positioned spans from the PDF content stream, for hidden-text detection (A01/A02).

    We parse `Tf` font sizes, `Tm`/`cm` text matrices and fill colours and record one span per text
    positioning operator. It does not need to be perfect - it only has to flag white, tiny or off-page text.
    """
    spans: list[dict[str, float]] = []
    try:
        box = page.mediabox
        pw, ph = float(box.width), float(box.height)
        content = page.get_contents()
        raw = content.get_data() if content is not None else b""
        stream = raw.decode("latin-1", errors="ignore")
    except Exception:  # noqa: BLE001
        return spans

    size = 10.0
    color = 0x000000
    x = y = 0.0
    # Walk operators in order; track the most recent size, colour and position.
    for match in re.finditer(r"/([A-Za-z0-9]+)\s+([\d.]+)\s+Tf|([-\d.]+ [-\d.]+ [-\d.]+ [-\d.]+ [-\d.]+ [-\d.]+)\s+Tm|([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+(rg|RG)|([\d.]+)\s+(g|G)|[^\s]+\s+Tj|\[[^\]]*\]\s*TJ", stream):
        if match.group(1) is not None:
            size = float(match.group(2))
        elif match.group(3) is not None:
            nums = [float(n) for n in match.group(3).split()]
            x, y = nums[4], nums[5]
            spans.append({"size": size, "x": x, "y": y, "page_w": pw, "page_h": ph, "color": color})
        elif match.group(4) is not None:
            r, g, b = (float(match.group(i)) for i in (4, 5, 6))
            color = (round(r * 255) << 16) | (round(g * 255) << 8) | round(b * 255)
        elif match.group(8) is not None:
            gray = round(float(match.group(8)) * 255)
            color = (gray << 16) | (gray << 8) | gray
    return spans


def load_document_for_reader(path: Path, *, filename: str | None = None) -> dict[str, Any]:
    data = path.read_bytes()
    mime = validate_upload(data, filename or path.name)
    text, meta, spans = extract_text(data, mime)
    doc = {"text": text, "doc_sha256": sha256_of(data), "metadata": meta, "filename": filename or path.name,
           "mime": mime}
    if spans:
        doc["spans"] = spans
    return doc
