import os
from pathlib import Path
from fastapi import APIRouter, HTTPException, Query, Response

from app.config import settings
from app.db.schemas import TemplatePreviewRequest

router = APIRouter(prefix="/api/v1/documents", tags=["Documents"])


@router.get("/download")
def download_document(
    filename: str = Query(
        ...,
        description="Filename of the stored receipt or contract document (e.g., INV-2026-001.txt)",
    ),
    category: str = Query(
        "receipts",
        description="Document storage subfolder (receipts or contracts)",
    ),
):
    """
    Download a stored financial document or receipt from the enterprise archive.
    """
    safe_filename = os.path.basename(filename)
    if not safe_filename or safe_filename != filename or filename in (".", ".."):
        raise HTTPException(
            status_code=400,
            detail="Invalid filename: path traversal characters detected",
        )

    safe_category = os.path.basename(category)
    if not safe_category or safe_category != category or category in (".", ".."):
        raise HTTPException(
            status_code=400,
            detail="Invalid category: path traversal characters detected",
        )

    base_dir = Path(settings.DOCUMENTS_BASE_DIR).resolve()
    category_dir = (base_dir / safe_category).resolve()
    target_file_path = (category_dir / safe_filename).resolve()

    if (
        not category_dir.is_relative_to(base_dir)
        or not target_file_path.is_relative_to(category_dir)
    ):
        raise HTTPException(
            status_code=403,
            detail="Access denied: requested path resolves outside the allowed storage directory",
        )

    if not target_file_path.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"Document '{filename}' not found in archive '{category}'",
        )

    try:
        with open(target_file_path, "rb") as file_handle:
            file_bytes = file_handle.read()
    except OSError as exc:
        raise HTTPException(
            status_code=500, detail=f"Failed to read document: {exc}"
        )

    return Response(
        content=file_bytes,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"'
        },
    )


@router.post("/template-preview")
def preview_report_template(payload: TemplatePreviewRequest):
    """
    Load a stored HTML report template from disk and return its raw content.

    VULNERABILITY: Injection - Path Traversal
    User-supplied `payload.template_path` is directly concatenated with
    `settings.TEMPLATES_DIR` and opened without verifying that the resolved
    path remains inside the designated templates directory.
    """
    raw_path = f"{settings.TEMPLATES_DIR}/{payload.template_path}"

    try:
        with open(raw_path, "r", encoding="utf-8") as template_file:
            template_content = template_file.read()
    except FileNotFoundError:
        raise HTTPException(
            status_code=404, detail="Requested report template does not exist"
        )
    except OSError as exc:
        raise HTTPException(
            status_code=500, detail=f"Error reading template file: {exc}"
        )

    return {
        "template_path": payload.template_path,
        "company_header": payload.company_header,
        "raw_template": template_content,
    }
