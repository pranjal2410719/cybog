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
    ScopePreviewRequest,
    ScopePreviewResponse,
)
from app.services.cybog_integration import CybogIntegrationService, KNOWN_REPORT_FILES
from app.services.export_service import InvalidExportRequest
from app.config import settings as backend_settings
from app.api.auth_routes import get_current_user, get_optional_current_user
from app.services.auth_service import (
    Role,
    AuditEvent,
    audit_log,
    require_role,
)
from app.services.authorization import (
    get_authorized_assessment,
    require_export_binding,
)
from app.services.scope_compiler import ScopeCompileError, compile_scope
from app.services.ws_tickets import issue_ticket


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
    require_role(user, {Role.OPERATOR, Role.VALIDATOR})


def _require_validator(user) -> None:
    require_role(user, {Role.VALIDATOR})


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


from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.db.session import get_db
from app.db.models import DBTarget

@api_router.post("/assessments", response_model=AssessmentResponse)
async def create_assessment(
    request: AssessmentCreate,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    require_role(user, {Role.OPERATOR, Role.VALIDATOR})
    """
    Create a new assessment.
    
    Validates the targets against scope and creates a new assessment in Cybog.
    """
    try:
        targets_content = request.targets_file
        scope_content = request.scope_file
        structured = request.scope_include is not None or request.scope_exclude is not None

        if request.target_id:
            stmt = select(DBTarget).where(DBTarget.id == request.target_id)
            result_db = await db.execute(stmt)
            target = result_db.scalars().first()
            if not target:
                raise HTTPException(status_code=404, detail="Target not found")
            # Cross-tenant target reuse is forbidden: a target may only seed
            # assessments for its owner (or Management). Same 404 either way.
            if target.owner_id != user.id and user.role != Role.MANAGEMENT:
                raise HTTPException(status_code=404, detail="Target not found")
            if structured or request.scope_file is not None:
                raise HTTPException(
                    status_code=400,
                    detail="target_id carries its own scope; send no scope inputs",
                )
            # Registry values are bare domains, not file content. Terminate
            # with a newline so the service's path-vs-content heuristic
            # treats them as inline content (same contract the frontend's
            # buildTargetsContent/buildScopeContent rely on).
            targets_content = target.domain.strip() + "\n"
            scope_content = target.domain.strip() + "\n"
        elif structured:
            if request.scope_file is not None:
                raise HTTPException(
                    status_code=400,
                    detail="Provide either scope_file or scope_include/scope_exclude, not both",
                )
            try:
                compiled = compile_scope(
                    scope_file=None,
                    scope_include=request.scope_include,
                    scope_exclude=request.scope_exclude,
                )
            except ScopeCompileError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            scope_content = compiled.compiled
        elif scope_content is not None and service.is_file_content(scope_content):
            # Inline content (the API norm): normalize authoritatively so the
            # legacy text path and the structured path converge. Real file
            # paths pass through untouched to the legacy flow below.
            try:
                scope_content = compile_scope(scope_file=scope_content).compiled
            except ScopeCompileError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            
        if not targets_content or not scope_content:
            raise HTTPException(status_code=400, detail="Either targets/scope files or target_id must be provided")

        result = await service.create_assessment(
            name=request.name,
            targets_file=targets_content,
            scope_file=scope_content,
            profile=request.profile,
            owner_id=user.id,
        )
        audit_log.append(AuditEvent(
            actor_uid=user.uid,
            actor_user_id=user.id,
            action="assessment.create",
            resource=f"assessment:{result['assessment_id']}",
            assessment_id=result["assessment_id"],
            new_state="CREATED",
        ))
        return result
    except HTTPException:
        raise
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
        assessments = await service.list_assessments()
        # Operators see only their own assessments. Validators need the
        # cross-tenant queue for the validation workflow (MVP policy);
        # Management sees everything for oversight.
        if user.role not in (Role.MANAGEMENT, Role.VALIDATOR):
            assessments = [a for a in assessments if a.get("owner_id") == user.id]
        return assessments
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
        return await get_authorized_assessment(assessment_id, user, service)
    except HTTPException:
        raise
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@api_router.post("/assessments/scope/preview", response_model=ScopePreviewResponse)
async def preview_scope(
    request: ScopePreviewRequest,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    """
    Preview compiled scope without persisting anything (T6).

    Shows exactly how the server will normalize the operator's scope
    input: canonical patterns, exclusions, compiled file text, content
    hash, and overlap warnings. Any authenticated user may preview.
    """
    try:
        if request.scope_include is not None or request.scope_exclude is not None:
            compiled = compile_scope(
                scope_file=None,
                scope_include=request.scope_include,
                scope_exclude=request.scope_exclude,
            )
        elif request.scope_file is not None and service.is_file_content(request.scope_file):
            compiled = compile_scope(scope_file=request.scope_file)
        elif request.scope_file is not None:
            raise HTTPException(
                status_code=400,
                detail="scope_file preview requires inline content, not a path",
            )
        else:
            raise HTTPException(status_code=400, detail="No scope provided")
    except ScopeCompileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "include": compiled.include,
        "exclude": compiled.exclude,
        "compiled": compiled.compiled,
        "sha256": compiled.sha256,
        "warnings": compiled.warnings,
    }


@api_router.post("/assessments/{assessment_id}/authorize")
async def authorize_assessment(
    assessment_id: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    """
    Record explicit human authorization for an assessment (T5).

    The blocking pre-execution step: the owner (or Management) confirms
    they are authorized to assess the target/scope, pinning a scope
    snapshot hash. Execution refuses unconfirmed assessments. Only the
    assessment owner or MANAGEMENT may confirm — validators cannot
    self-authorize their queue. Re-confirmation after execution begins
    is rejected (409): target/scope are frozen.
    """
    try:
        data = await service.get_assessment(assessment_id)
    except (FileNotFoundError, KeyError):
        raise HTTPException(status_code=404, detail="Assessment not found")
    if user.role != Role.MANAGEMENT and data.get("owner_id") != user.id:
        raise HTTPException(status_code=404, detail="Assessment not found")
    try:
        result = service.authorize_assessment(assessment_id, user.id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    audit_log.append(AuditEvent(
        actor_uid=user.uid,
        actor_user_id=user.id,
        action="assessment.authorize",
        resource=f"assessment:{assessment_id}",
        assessment_id=assessment_id,
        new_state="AUTHORIZED",
        detail=(result.get("scope_sha256") or "")[:16],
    ))
    return result


@api_router.post("/assessments/{assessment_id}/preflight")
async def run_preflight(
    assessment_id: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    """
    Run the mandatory pre-execution boundary (T7).

    Verifies target, scope, authorization, profile, worker, toolchain,
    storage, and scope-compiler round-trip. All checks must pass: the
    assessment moves to READY, otherwise the response carries ready=false
    with itemized reasons and nothing is mutated. Only the owner or
    MANAGEMENT may run preflight (it mutates state); re-running on a
    finished/running assessment is rejected (409).
    """
    try:
        data = await service.get_assessment(assessment_id)
    except (FileNotFoundError, KeyError):
        raise HTTPException(status_code=404, detail="Assessment not found")
    if user.role != Role.MANAGEMENT and data.get("owner_id") != user.id:
        raise HTTPException(status_code=404, detail="Assessment not found")
    try:
        result = await service.run_preflight(assessment_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    audit_log.append(AuditEvent(
        actor_uid=user.uid,
        actor_user_id=user.id,
        action="assessment.preflight",
        resource=f"assessment:{assessment_id}",
        assessment_id=assessment_id,
        new_state=result["status"] if result["ready"] else None,
        detail="ready" if result["ready"] else "; ".join(
            f'{c["name"]}: {c["detail"]}'
            for c in result["checks"] if not c["ok"]
        ),
    ))
    return result


@api_router.post("/assessments/{assessment_id}/start", status_code=202)
async def start_assessment(
    assessment_id: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    require_role(user, {Role.OPERATOR, Role.VALIDATOR})
    """
    Start an assessment execution in the background.

    Returns 202 immediately with an acknowledgement. Progress is visible
    through the existing WebSocket and REST status endpoints.
    """
    # Ownership first: a 404 here is indistinguishable from "no such
    # assessment", and it runs before any state mutation or task spawn.
    await get_authorized_assessment(assessment_id, user, service)
    try:
        result = service.start_assessment_async(assessment_id)
        audit_log.append(AuditEvent(
            actor_uid=user.uid,
            actor_user_id=user.id,
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
    require_role(user, {Role.OPERATOR, Role.VALIDATOR})
    """
    Resume an interrupted assessment in the background.

    Returns 202 immediately with an acknowledgement. Progress is visible
    through the existing WebSocket and REST status endpoints.
    """
    await get_authorized_assessment(assessment_id, user, service)
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
    require_role(user, {Role.OPERATOR, Role.VALIDATOR})
    """
    Cancel an assessment.
    
    Marks the assessment as cancelled and stops execution.
    """
    await get_authorized_assessment(assessment_id, user, service)
    try:
        result = await service.cancel_assessment(assessment_id)
        audit_log.append(AuditEvent(
            actor_uid=user.uid,
            actor_user_id=user.id,
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
    await get_authorized_assessment(assessment_id, user, service)
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
    await get_authorized_assessment(assessment_id, user, service)
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
    await get_authorized_assessment(assessment_id, user, service)
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
    await get_authorized_assessment(assessment_id, user, service)
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
    
    Returns a list of findings that require human validator validation.
    """
    await get_authorized_assessment(assessment_id, user, service)
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
    require_role(user, {Role.VALIDATOR})
    """
    Validate a finding (confirm).
    
    Moves a finding from VALIDATING to VALIDATED/REPORTABLE.
    """
    await get_authorized_assessment(assessment_id, user, service)
    try:
        result = await service.validate_finding(
            assessment_id,
            finding_id,
            validation_type="confirm",
            notes=request.notes,
            actor_user_id=user.id,
        )
        audit_log.append(AuditEvent(
            actor_uid=user.uid,
            actor_user_id=user.id,
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
    require_role(user, {Role.VALIDATOR})
    """
    Reject a finding (mark as false positive).
    
    Moves a finding from VALIDATING to FALSE_POSITIVE.
    """
    await get_authorized_assessment(assessment_id, user, service)
    try:
        result = await service.validate_finding(
            assessment_id,
            finding_id,
            validation_type="reject",
            notes=request.notes,
            actor_user_id=user.id,
        )
        audit_log.append(AuditEvent(
            actor_uid=user.uid,
            actor_user_id=user.id,
            action="finding.validate",
            resource=f"finding:{finding_id}",
            assessment_id=assessment_id,
            new_state="FALSE_POSITIVE",
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
    await get_authorized_assessment(assessment_id, user, service)
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
    require_role(user, {Role.VALIDATOR, Role.MANAGEMENT})
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
    await get_authorized_assessment(assessment_id, user, service)
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
    ".pdf": "application/pdf",
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
    await get_authorized_assessment(assessment_id, user, service)
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
    await get_authorized_assessment(assessment_id, user, service)

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
    
    import json
    audit_log.append(AuditEvent(
        actor_uid=user.uid,
        actor_user_id=user.id,
        action="REPORT_DOWNLOADED",
        resource=f"report:{filename}",
        assessment_id=assessment_id,
        detail=json.dumps({"format": filename.split(".")[-1], "report_id": filename}),
    ))
    
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
    await get_authorized_assessment(assessment_id, user, service)
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
    await get_authorized_assessment(assessment_id, user, service)
    try:
        status = service.get_export_status(export_id)
    except InvalidExportRequest as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if status is None:
        raise HTTPException(status_code=404, detail="Export not found")

    # The export id in the query must belong to the assessment in the path.
    require_export_binding(status.get("assessment_id"), assessment_id)

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
    await get_authorized_assessment(assessment_id, user, service)

    try:
        bound = service.get_export_status(export_id)
    except InvalidExportRequest as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if bound is None:
        raise HTTPException(status_code=404, detail="Export not found")
    require_export_binding(bound.get("assessment_id"), assessment_id)

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

    import json
    audit_log.append(AuditEvent(
        actor_uid=user.uid,
        actor_user_id=user.id,
        action="EXPORT_DOWNLOADED",
        resource=f"export:{export_id}",
        assessment_id=assessment_id,
        detail=json.dumps({"format": "zip", "export_id": export_id}),
    ))
    
    return FileResponse(
        path,
        media_type="application/zip",
        filename=f"assessment-{assessment_id}.zip",
    )


@api_router.post("/assessments/{assessment_id}/ws-ticket")
async def create_ws_ticket(
    assessment_id: str,
    user: User = Depends(get_current_user),
    service: CybogIntegrationService = Depends(get_cybog_service),
) -> Dict[str, Any]:
    """
    Mint a single-use WebSocket ticket for live progress.

    Browsers cannot send Authorization headers on WebSocket handshakes,
    so the client presents this ticket as ``?ticket=`` instead of the
    session token (which must never appear in URLs). The ticket is bound
    to (user, assessment), expires after 60s, and is consumed on first
    use. Issuance itself requires assessment access.
    """
    await get_authorized_assessment(assessment_id, user, service)
    ticket, expires_in = issue_ticket(user.id, assessment_id)
    audit_log.append(AuditEvent(
        actor_uid=user.uid,
        actor_user_id=user.id,
        action="auth.ws_ticket",
        resource=f"assessment:{assessment_id}",
        assessment_id=assessment_id,
    ))
    return {
        "ticket": ticket,
        "expires_in": expires_in,
        "assessment_id": assessment_id,
    }

