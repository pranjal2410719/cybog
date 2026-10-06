"""
Centralized assessment authorization (T2: tenant isolation).

Single enforcement point for every assessment-scoped route and, later,
the WebSocket handshake (T3). Policy (frozen R2 + MVP validator policy):

- MANAGEMENT  -> any assessment (oversight).
- owner       -> own assessments (``state.assessment.owner_id == user.id``).
- VALIDATOR   -> any assessment (MVP: validators work one shared queue;
  restrict to assignments later without touching call sites).
- other OPERATORs -> 404 (no existence oracle: indistinguishable from
  "assessment does not exist").
- unauthenticated -> 401 (via ``get_current_user``).
- role violations (e.g. OPERATOR calling validate) -> 403 (via
  ``require_role`` at the route, before this module runs).

Client-supplied ids are lookup keys only; ownership and role are always
resolved server-side from the session user.
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import HTTPException

from app.models.auth import Role, User


async def get_authorized_assessment(
    assessment_id: str,
    user: User,
    service: Any,
) -> Dict[str, Any]:
    """
    Load an assessment and enforce tenant access.

    Returns the assessment response dict. Raises 404 when the assessment
    does not exist or the user may not access it. Service-layer failures
    other than not-found propagate to the caller's handlers.
    """
    try:
        data = await service.get_assessment(assessment_id)
    except (FileNotFoundError, KeyError):
        raise HTTPException(status_code=404, detail="Assessment not found")
    if user.role == Role.MANAGEMENT:
        return data
    owner_id = data.get("owner_id")
    if owner_id is not None and owner_id == user.id:
        return data
    if user.role == Role.VALIDATOR:
        # MVP validation-queue policy: any validator may read/validate any
        # assessment. Narrow to assignments later (T8+); call sites stay put.
        return data
    raise HTTPException(status_code=404, detail="Assessment not found")


def require_export_binding(status_assessment_id: str | None, assessment_id: str) -> None:
    """
    Ensure an export record belongs to the assessment in the URL path.

    Export ids are unguessable (uuid4) but must still not be swappable
    across assessments. Missing/mismatched binding -> 404.
    """
    if not status_assessment_id or status_assessment_id != assessment_id:
        raise HTTPException(status_code=404, detail="Export not found")
