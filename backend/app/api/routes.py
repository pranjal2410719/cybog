"""
Cybog backend API routes.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from fastapi.responses import FileResponse, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.models.api import (
    AssessmentCreate,
    AssessmentResponse,
    ExportRequest,
    ExportResponse,
    FileUploadResponse,
    FindingResponse,
    FindingValidationRequest,
    HealthResponse,
)
from app.services.cybog_integration import CybogIntegrationService, KNOWN_REPORT_FILES
from app.services.export_service import InvalidExportRequest
from app.config import settings as backend_settings
from app.api.auth_routes import get_current_user, get_optional_current_user
from app.services.auth_service import (
    Role,
    AuditEvent,
    audit_log,
    get_current_user as _resolve_user,
    require_role,
)


api_router = APIRouter(prefix="/api/v1")

# Security scheme (placeholder for now - auth to be added later)
security = HTTPBearer(auto_error=False)


def get_cybog_service() -> CybogIntegrationService:
    """
    Get the Cybog integration service instance.

    CYBOG_OUTPUT_ROOT is applied as an override on top of the loaded
    config.yaml. Without this the variable was decorative — it was logged at
    startup but never reached the config the service actually used, so the
    dashboard read a different directory than the operator configured.

    A relative output.root in config.yaml resolves against the process working
    directory, so an explicit absolute root is also what keeps the backend
    reading the same assessments regardless of where it was launched from.
    """
    from cybog.config.loader import load_config

    config = load_config(backend_settings.CYBOG_CONFIG_PATH)

    override = backend_settings.CYBOG_OUTPUT_ROOT
    if override:
        config.output.root = str(Path(override).expanduser())

    return CybogIntegrationService(config)




def _require_operator(user) -> None:
    require_role(user, {Role.OPERATOR, Role.ANALYST})


def _require_analyst(user) -> None:
    require_role(user, {Role.ANALYST})


@api_router.post("/files/upload", response_model=FileUploadResponse)
async def upload_file(
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    """
    Upload a file (targets.txt or scope.txt) and return its content.
    
    The file content can then be used in the assessment creation request.
    """
    try:
        # Validate file extension
        allowed_extensions = {'.txt'}
        file_ext = Path(file.filename).suffix.lower()
        if file_ext not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"File extension {file_ext} not allowed. Allowed: {allowed_extensions}"
            )
        
        # Validate file size (10MB limit)
        content = await file.read()
        if len(content) > 10 * 1024 * 1024:  # 10MB
            raise HTTPException(
                status_code=400,
                detail="File size exceeds 10MB limit"
            )
        
        # Reset and read as UTF-8 text
        await file.seek(0)
        content_str = (await file.read()).decode('utf-8')
        
        # Validate content is valid UTF-8
        try:
            content_str.encode('utf-8')
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=400,
                detail="File is not valid UTF-8 text"
            )
        
        # Secure filename to prevent path traversal
        import uuid
        secure_filename = f"{uuid.uuid4()}{file_ext}"
        
        # Save to temp directory for reference
        temp_dir = Path(service.config.output.root) / "temp_uploads"
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        file_path = temp_dir / secure_filename
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content_str)
        
        return {
            "filename": file.filename,
            "secure_filename": secure_filename,
            "file_path": str(file_path),
            "content": content_str,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api_router.get("/health", response_model=HealthResponse)
async def health_check(
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Health check endpoint.
    
    Returns the health status of the backend and Cybog integration.
    """
    try:
        import cybog
        return {
            "status": "healthy",
            "version": "1.0.0",
            "cybog_version": cybog.__version__,
        }
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@api_router.post("/assessments", response_model=AssessmentResponse)
async def create_assessment(
    request: AssessmentCreate,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    require_role(user, {Role.OPERATOR, Role.ANALYST})
    """
    Create a new assessment.
    
    Validates the targets against scope and creates a new assessment in Cybog.
    """
    try:
        result = await service.create_assessment(
            name=request.name,
            targets_file=request.targets_file,
            scope_file=request.scope_file,
            profile=request.profile,
        )
        audit_log.append(AuditEvent(
            actor_uid=user.uid,
            action="assessment.create",
            resource=f"assessment:{result['assessment_id']}",
            assessment_id=result["assessment_id"],
            new_state="CREATED",
        ))
        return result
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api_router.get("/assessments", response_model=List[AssessmentResponse])
async def list_assessments(
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> List[Dict[str, Any]]:
    """
    List all assessments.

    Returns a list of all assessments with their current status.
    """
    try:
        return await service.list_assessments()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@api_router.get(
    "/assessments/{assessment_id}", response_model=AssessmentResponse
)
async def get_assessment(
    assessment_id: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    """
    Get assessment details by ID.
    
    Returns the full assessment information including targets and configuration.
    """
    try:
        result = await service.get_assessment(assessment_id)
        return result
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@api_router.post("/assessments/{assessment_id}/start", status_code=202)
async def start_assessment(
    assessment_id: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    require_role(user, {Role.OPERATOR, Role.ANALYST})
    """
    Start an assessment execution in the background.

    Returns 202 immediately with an acknowledgement. Progress is visible
    through the existing WebSocket and REST status endpoints.
    """
    try:
        result = service.start_assessment_async(assessment_id)
        audit_log.append(AuditEvent(
            actor_uid=user.uid,
            action="assessment.start",
            resource=f"assessment:{assessment_id}",
            assessment_id=assessment_id,
            new_state="STARTING",
        ))
        return result
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api_router.post("/assessments/{assessment_id}/resume", status_code=202)
async def resume_assessment(
    assessment_id: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    """
    Resume an interrupted assessment in the background.

    Returns 202 immediately with an acknowledgement. Progress is visible
    through the existing WebSocket and REST status endpoints.
    """
    try:
        result = service.resume_assessment_async(assessment_id)
        return result
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api_router.post("/assessments/{assessment_id}/cancel")
async def cancel_assessment(
    assessment_id: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    require_role(user, {Role.OPERATOR, Role.ANALYST})
    """
    Cancel an assessment.
    
    Marks the assessment as cancelled and stops execution.
    """
    try:
        result = await service.cancel_assessment(assessment_id)
        audit_log.append(AuditEvent(
            actor_uid=user.uid,
            action="assessment.cancel",
            resource=f"assessment:{assessment_id}",
            assessment_id=assessment_id,
            new_state="CANCELLING",
        ))
        return {"assessment_id": assessment_id, "cancelled": result}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api_router.get("/assessments/{assessment_id}/status")
async def get_assessment_status(
    assessment_id: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    """
    Get assessment status and progress.
    
    Returns the current status including progress percentage and per-target completion.
    """
    try:
        result = await service.get_assessment_status(assessment_id)
        return result
    except (FileNotFoundError, KeyError) as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api_router.get("/assessments/{assessment_id}/progress")
async def get_assessment_progress(
    assessment_id: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    """
    Get detailed progress for an assessment.
    
    Returns per-stage and per-target progress information.
    """
    try:
        result = await service.get_assessment_status(assessment_id)
        return result
    except (FileNotFoundError, KeyError) as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api_router.get(
    "/assessments/{assessment_id}/findings", response_model=List[FindingResponse]
)
async def get_findings(
    assessment_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> List[Dict[str, Any]]:
    """
    Get findings for an assessment.
    
    Returns all findings with optional severity filtering.
    """
    try:
        findings = await service.get_findings(assessment_id, severity)
        return findings
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api_router.get("/assessments/{assessment_id}/findings/{finding_id}")
async def get_finding(
    assessment_id: str,
    finding_id: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    """
    Get a specific finding by ID.
    
    Returns detailed information about a single finding.
    """
    try:
        findings = await service.get_findings(assessment_id)
        for finding in findings:
            if finding["finding_id"] == finding_id:
                return finding
        raise HTTPException(status_code=404, detail="Finding not found")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api_router.get("/assessments/{assessment_id}/validation/pending")
async def get_pending_validation(
    assessment_id: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    """
    Get findings awaiting validation.
    
    Returns a list of findings that require human analyst validation.
    """
    try:
        pending = await service.get_pending_validation(assessment_id)
        return {
            "assessment_id": assessment_id,
            "pending_count": len(pending),
            "findings": pending,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api_router.post("/assessments/{assessment_id}/findings/{finding_id}/validate")
async def validate_finding(
    assessment_id: str,
    finding_id: str,
    request: FindingValidationRequest,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    require_role(user, {Role.ANALYST})
    """
    Validate a finding (confirm).
    
    Moves a finding from VALIDATING to VALIDATED/REPORTABLE.
    """
    try:
        result = await service.validate_finding(
            assessment_id,
            finding_id,
            validation_type="confirm",
            notes=request.notes,
        )
        audit_log.append(AuditEvent(
            actor_uid=user.uid,
            action="finding.validate",
            resource=f"finding:{finding_id}",
            assessment_id=assessment_id,
            new_state="VALIDATED",
            detail=request.notes,
        ))
        return {"success": result, "finding_id": finding_id}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api_router.post("/assessments/{assessment_id}/findings/{finding_id}/reject")
async def reject_finding(
    assessment_id: str,
    finding_id: str,
    request: FindingValidationRequest,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    require_role(user, {Role.ANALYST})
    """
    Reject a finding (mark as false positive).
    
    Moves a finding from VALIDATING to FALSE_POSITIVE.
    """
    try:
        result = await service.validate_finding(
            assessment_id,
            finding_id,
            validation_type="reject",
            notes=request.notes,
        )
        audit_log.append(AuditEvent(
            actor_uid=user.uid,
            action="finding.validate",
            resource=f"finding:{finding_id}",
            assessment_id=assessment_id,
            new_state="VALIDATED",
            detail=request.notes,
        ))
        return {"success": result, "finding_id": finding_id}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api_router.get("/assessments/{assessment_id}/artifacts")
async def get_assessment_artifacts(
    assessment_id: str,
    artifact_type: str = Query("all", description="Type of artifacts"),
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    """
    Get artifacts for an assessment.
    
    Returns metadata about assessment artifacts (raw output, reports, etc.).
    """
    try:
        artifacts = await service.get_assessment_artifacts(assessment_id, artifact_type)
        return {
            "assessment_id": assessment_id,
            "artifacts": artifacts,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api_router.get("/audit/events")
async def list_audit_events(
    assessment_id: Optional[str] = Query(None),
    user=Depends(get_current_user),
):
    require_role(user, {Role.ANALYST, Role.MANAGEMENT})
    events = audit_log.list(assessment_id=assessment_id)
    return {"events": [e.model_dump(mode="json") for e in events]}


@api_router.get("/assessments/{assessment_id}/reports")
async def get_assessment_reports(
    assessment_id: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    """
    Get generated reports for an assessment.
    
    Returns metadata about generated reports (JSON, JSONL, HTML) including
    filename, type, size in bytes, and whether the file exists on disk.
    """
    try:
        reports = await service.get_assessment_reports(assessment_id)
        return {
            "assessment_id": assessment_id,
            "reports": reports,
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Assessment not found")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# Report file serving endpoints

# Content-Type mapping for known report formats
_REPORT_MEDIA_TYPES = {
    ".json": "application/json",
    ".jsonl": "application/jsonl",
    ".html": "text/html",
}

# Allowlist for valid report filenames (prevents path traversal)
# ``fullmatch`` (not ``match``) so a trailing newline is not accepted.
_REPORT_FILENAME_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")
# Structural characters that are never valid inside a report filename.
_TRAVERSAL_MARKERS = ("..", "/", "\\", "\x00")


class UnknownReportFile(InvalidExportRequest):
    """Well-formed filename that is not a report the pipeline produces.

    Kept distinct from a malformed/traversal request so the API can answer 404
    (no such resource) instead of leaking which filenames are allowlisted.
    """


def _validate_report_filename(filename: str) -> None:
    """Validate report filename against the allowlist and traversal rules."""
    if any(marker in filename for marker in _TRAVERSAL_MARKERS):
        raise InvalidExportRequest("Path traversal attempt in filename")
    if _REPORT_FILENAME_RE.fullmatch(filename) is None:
        # Empty, over-length, or outside [A-Za-z0-9._-].
        raise InvalidExportRequest("Invalid report filename")
    if filename not in KNOWN_REPORT_FILES:
        raise UnknownReportFile("Unknown report file")


def _get_media_type(filename: str) -> str:
    """Get media type for a report filename."""
    for ext, media_type in _REPORT_MEDIA_TYPES.items():
        if filename.endswith(ext):
            return media_type
    return "application/octet-stream"


def _add_conditional_headers(response: Response, file_path: Path) -> None:
    """Add ETag, Last-Modified, and Content-Length headers for conditional requests."""
    import hashlib
    import time
    stat = file_path.stat()
    response.headers["Content-Length"] = str(stat.st_size)
    # ETag: hash of filename + size + mtime
    etag_data = f"{file_path.name}:{stat.st_size}:{stat.st_mtime}"
    response.headers["ETag"] = f'"{hashlib.md5(etag_data.encode()).hexdigest()}"'
    response.headers["Last-Modified"] = time.strftime(
        "%a, %d %b %Y %H:%M:%S GMT", time.gmtime(stat.st_mtime)
    )


@api_router.get("/assessments/{assessment_id}/reports/{filename:path}/inline")
async def view_report_inline(
    assessment_id: str,
    filename: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> FileResponse:
    """
    View an HTML report inline (hardened).

    Only serves report.html with a strict Content-Security-Policy to prevent
    execution of attacker-influenced content. Other formats return 404.
    
    Security headers:
    - Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:
    - X-Content-Type-Options: nosniff
    - Content-Disposition: inline
    - Referrer-Policy: no-referrer
    
    Note: Inline viewing is still risky. The CSP prevents script execution and
    external resource loads, but cannot prevent:
    - CSS-based exfiltration (limited by style-src 'unsafe-inline')
    - UI redressing/clickjacking (no frame-ancestors directive here)
    - Data URI images (allowed via img-src data:)
    - Browser bugs in CSP enforcement
    
    Default behavior should be the download endpoint above.
    """
    # Validate filename: malformed/traversal -> 400, not-a-report -> 404
    try:
        _validate_report_filename(filename)
    except UnknownReportFile:
        raise HTTPException(status_code=404, detail="Report not found")
    except InvalidExportRequest as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Only allow HTML for inline viewing
    if not filename.lower().endswith('.html'):
        raise HTTPException(status_code=404, detail="Inline viewing only supported for HTML reports")

    # Get the file path from service (validates traversal and symlinks)
    try:
        file_path = await service.get_assessment_report_file_inline(assessment_id, filename)
    except UnknownReportFile:
        raise HTTPException(status_code=404, detail="Report not found")
    except InvalidExportRequest as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    if file_path is None or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")

    # Build response with hardened security headers
    response = FileResponse(
        file_path,
        media_type="text/html",
        filename=filename,
        headers={
            "Content-Disposition": f'inline; filename="{filename}"',
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:;",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )
    _add_conditional_headers(response, file_path)
    return response


@api_router.get("/assessments/{assessment_id}/reports/{filename:path}")
async def download_report(
    assessment_id: str,
    filename: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> FileResponse:
    """
    Download a generated report file.

    Serves JSON, JSONL, and HTML reports as attachments.
    Returns 404 if the report does not exist or the assessment is not found.
    """
    # Validate filename: malformed/traversal -> 400, not-a-report -> 404
    try:
        _validate_report_filename(filename)
    except UnknownReportFile:
        raise HTTPException(status_code=404, detail="Report not found")
    except InvalidExportRequest as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Get the file path from service (validates traversal and symlinks)
    try:
        file_path = await service.get_assessment_report_file(assessment_id, filename)
    except UnknownReportFile:
        raise HTTPException(status_code=404, detail="Report not found")
    except InvalidExportRequest as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    if file_path is None or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")

    # Determine media type
    media_type = _get_media_type(filename)

    # Build response with conditional headers
    response = FileResponse(
        file_path,
        media_type=media_type,
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
    _add_conditional_headers(response, file_path)
    return response


@api_router.post("/assessments/{assessment_id}/export", response_model=ExportResponse)
async def create_export(
    assessment_id: str,
    request: ExportRequest,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    """
    Create an export of assessment results.

    Generates a ZIP archive of the assessment output.
    """
    try:
        result = await service.create_export(
            assessment_id,
            request.format,
            include_raw=request.include_raw,
            include_evidence=request.include_evidence,
            include_validated_only=request.include_validated_only,
        )
        return result
    except HTTPException:
        raise
    except InvalidExportRequest as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api_router.get("/assessments/{assessment_id}/export/status")
async def get_export_status(
    assessment_id: str,
    export_id: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    """
    Get export status.

    Returns the status of an export task, read from the persisted export
    record. Returns 404 when the export id is unknown or unsafe.
    """
    try:
        status = service.get_export_status(export_id)
    except InvalidExportRequest as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if status is None:
        raise HTTPException(status_code=404, detail="Export not found")

    payload: Dict[str, Any] = {
        "export_id": status.get("export_id", export_id),
        "assessment_id": status.get("assessment_id", assessment_id),
        "format": status.get("format", "zip"),
        "status": status.get("status", "unknown"),
        "created_at": status.get("created_at"),
        "estimated_completion": status.get("completed_at"),
        "error": status.get("error"),
        "file_size_bytes": status.get("file_size_bytes"),
        "file_count": status.get("file_count"),
    }
    return payload


@api_router.get("/assessments/{assessment_id}/export/download")
async def download_export(
    assessment_id: str,
    export_id: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> FileResponse:
    """
    Download an export file.

    Returns the ZIP file for the assessment export.
    """
    try:
        info = service.get_export_download_info(export_id)
    except InvalidExportRequest as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if info is None:
        raise HTTPException(status_code=404, detail="Export not found")

    path: Optional[Path] = info.get("path")
    if not info.get("ready") or path is None:
        raise HTTPException(
            status_code=404,
            detail=f"Export not ready (status: {info.get('status') or 'unknown'})",
        )
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Export file missing")

    return FileResponse(
        path,
        media_type="application/zip",
        filename=f"assessment-{assessment_id}.zip",
    )

