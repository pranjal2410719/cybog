"""
Single-use WebSocket tickets (T3: WS authentication).

Browsers cannot set Authorization headers on WebSocket handshakes, so the
session Bearer token cannot travel on the socket. Instead, an
authenticated REST call mints a short-lived, single-use ticket bound to
(user_id, assessment_id); the client presents it as a ``?ticket=`` query
parameter and the WS endpoint redeems it **before** ``accept()``.

- TTL 60s, single-use (redeem pops the record).
- The session token itself never appears in URLs (no log leakage).
- Store is in-process and ephemeral: restarts invalidate tickets, which
  is the safe default. Multi-worker deployments need a shared store
  (Redis is already a declared dependency) — recorded future work.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

WS_TICKET_TTL_SECONDS = 60


@dataclass
class _Ticket:
    user_id: str
    assessment_id: str
    expires_at: float


_TICKETS: Dict[str, _Ticket] = {}
_lock = threading.Lock()


def issue_ticket(user_id: str, assessment_id: str,
                 ttl_seconds: int = WS_TICKET_TTL_SECONDS) -> Tuple[str, int]:
    """Mint a ticket bound to (user_id, assessment_id). Returns (ticket, ttl)."""
    ticket = secrets.token_urlsafe(24)
    with _lock:
        _purge_locked()
        _TICKETS[ticket] = _Ticket(
            user_id=user_id,
            assessment_id=assessment_id,
            expires_at=time.monotonic() + ttl_seconds,
        )
    return ticket, ttl_seconds


def redeem_ticket(ticket: Optional[str]) -> Optional[Tuple[str, str]]:
    """
    Consume a ticket, returning (user_id, assessment_id).

    Returns None for missing, unknown, expired, or already-used tickets.
    Single-use: the record is popped even on expiry so replays always fail.
    """
    if not ticket:
        return None
    with _lock:
        record = _TICKETS.pop(ticket, None)
        _purge_locked()
    if record is None:
        return None
    if record.expires_at < time.monotonic():
        return None
    return record.user_id, record.assessment_id


def _purge_locked() -> None:
    now = time.monotonic()
    expired = [t for t, r in _TICKETS.items() if r.expires_at < now]
    for t in expired:
        del _TICKETS[t]
