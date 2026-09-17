import os
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

    VULNERABILITY: Injection - Path Traversal
    The user-controlled `category` and `filename` parameters are joined with
    `os.path.join` without canonicalization (`Path.resolve()`) or base-directory
    boundary validation (`is_relative_to()`), allowing attackers to traverse
    arbitrary directories via `../` sequences (e.g., `filename=../../../../etc/passwd`).
    """
    # Vulnerable path construction: no sanitization or containment check
    target_file_path = os.path.join(
        str(settings.DOCUMENTS_BASE_DIR), category, filename
    )

    if not os.path.exists(target_file_path):
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
            "Content-Disposition": f'attachment; filename="{os.path.basename(filename)}"'
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
