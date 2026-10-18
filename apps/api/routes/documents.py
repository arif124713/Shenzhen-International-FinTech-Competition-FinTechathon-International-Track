"""Document upload: validate, extract text, run the isolated reader, return ReaderOutput (US-02)."""
from __future__ import annotations

import html
import uuid

from fastapi import APIRouter, File, HTTPException, UploadFile

from ..agents.llm import LLMError
from ..agents.reader import read_document
from ..agents.reader.schema import SanitizeError
from ..services.documents import UploadError, extract_text, sha256_of, validate_upload
from ..services.runtime import get_runtime
from ..settings import settings

router = APIRouter(tags=["documents"])


@router.post("/documents")
async def upload_document(file: UploadFile = File(...)) -> dict:  # noqa: B008
    rt = get_runtime()
    data = await file.read()
    try:
        mime = validate_upload(data, file.filename or "upload")
    except UploadError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code}) from exc

    doc_id = f"doc_{uuid.uuid4().hex[:12]}"
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    stored = settings.uploads_dir / f"{doc_id}.bin"  # random name, outside any static root
    stored.write_bytes(data)

    text, meta, spans = extract_text(data, mime)
    try:
        reader, flags = read_document({"text": text, "doc_sha256": sha256_of(data), "metadata": meta,
                                       "filename": file.filename or "upload"}, rt.reader_client.complete,
                                      detector_spans=spans)
    except (SanitizeError, LLMError) as exc:
        # The reader failed closed (invalid model output after retry, or no offline fixture). Never
        # crash with a 500: return a typed problem response so the UI can explain it (CLAUDE.md §5).
        raise HTTPException(status_code=422, detail={"code": "READER_UNAVAILABLE",
                                                     "message": str(exc)[:200]}) from exc
    return {
        "document_id": doc_id,
        "mime": mime,
        "reader": reader.model_dump(mode="json"),
        "anomalies": list(flags),
        # raw text is only ever returned escaped and clearly labeled untrusted (invariant 5)
        "untrusted_text": html.escape(text[:2000]),
    }
