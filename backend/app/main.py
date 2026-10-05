"""
Cybog backend main application.
"""
from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Dict, Set, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import api_router, get_cybog_service
from app.api.auth_routes import auth_router
from app.config import get_settings
from app.services.progress_snapshot import (
    build_progress_snapshot,
    is_terminal_snapshot,
    not_found_snapshot,
)

logger = logging.getLogger(__name__)

#: How often the broadcaster re-reads persisted state while an assessment is
#: still running. The scheduler saves state after every job
#: (cybog/workflow/scheduler.py:292), so this interval bounds staleness.
PROGRESS_PUSH_INTERVAL_SECONDS = 1.0


class ConnectionManager:
    """Manage WebSocket connections for live progress updates."""
    
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
    
    async def connect(self, assessment_id: str, websocket: WebSocket):
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        if assessment_id not in self.active_connections:
            self.active_connections[assessment_id] = set()
        self.active_connections[assessment_id].add(websocket)
        logger.info(f"WebSocket connected for assessment {assessment_id}")
    
    def disconnect(self, assessment_id: str, websocket: WebSocket):
        """Remove a WebSocket connection."""
        if assessment_id in self.active_connections:
            self.active_connections[assessment_id].discard(websocket)
            if not self.active_connections[assessment_id]:
                del self.active_connections[assessment_id]
        logger.info(f"WebSocket disconnected for assessment {assessment_id}")
    
    async def send_to_assessment(self, assessment_id: str, message: dict):
        """Send a message to all connections for an assessment."""
        if assessment_id in self.active_connections:
            dead_connections = set()
            for connection in self.active_connections[assessment_id]:
                try:
                    await connection.send_text(json.dumps(message, default=str))
                except Exception:
                    dead_connections.add(connection)
            
            # Clean up dead connections
            for conn in dead_connections:
                self.active_connections[assessment_id].discard(conn)


# Global connection manager
manager = ConnectionManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    # Startup
    settings = get_settings()
    logger.info(f"Starting Cybog Backend API in {settings.CYBOG_RUNTIME} mode")
    logger.info(f"Output root: {settings.CYBOG_OUTPUT_ROOT}")
    logger.info(f"Config path: {settings.CYBOG_CONFIG_PATH}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Cybog Backend API")


app = FastAPI(
    title="Cybog Backend API",
    description="API for managing Cybog assessments",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
from app.api.target_routes import target_router
app.include_router(api_router)
app.include_router(auth_router)
app.include_router(target_router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "Cybog Backend API",
        "version": "1.0.0",
        "status": "running",
    }


@app.get("/health")
async def health():
    """Simple health check endpoint."""
    return {"status": "healthy", "version": "1.0.0"}


async def _load_snapshot(assessment_id: str) -> Dict[str, object]:
    """
    Read the real AssessmentState for an assessment and project it to a snapshot.

    Raises FileNotFoundError when the assessment has no persisted state.
    """
    service = get_cybog_service()
    state = service.load_state(assessment_id)
    return build_progress_snapshot(state, assessment_id)


async def push_progress_loop(
    assessment_id: str,
    interval: Optional[float] = None,
    stop_event: Optional[asyncio.Event] = None,
    max_iterations: Optional[int] = None,
) -> None:
    """
    Push real state-derived progress snapshots for an assessment.

    Re-reads persisted state on every tick and broadcasts through the existing
    ConnectionManager. Returns as soon as the assessment reaches a terminal
    status, the client disconnects, the stop event is set, or the state file
    disappears. Never fabricates or interpolates values.
    """
    wait = PROGRESS_PUSH_INTERVAL_SECONDS if interval is None else interval
    iterations = 0

    while True:
        if stop_event is not None and stop_event.is_set():
            return
        if assessment_id not in manager.active_connections:
            return

        try:
            snapshot = await _load_snapshot(assessment_id)
        except FileNotFoundError:
            await manager.send_to_assessment(
                assessment_id, not_found_snapshot(assessment_id)
            )
            return
        except Exception:
            logger.exception(
                f"Failed to build progress snapshot for {assessment_id}"
            )
            return

        await manager.send_to_assessment(assessment_id, snapshot)
        iterations += 1

        if max_iterations is not None and iterations >= max_iterations:
            return
        if is_terminal_snapshot(snapshot):
            logger.info(
                f"Assessment {assessment_id} reached {snapshot.get('status')}; "
                "stopping progress push"
            )
            return

        if stop_event is not None:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=wait)
                return
            except (asyncio.TimeoutError, TimeoutError):
                pass
        else:
            await asyncio.sleep(wait)


@app.websocket("/ws/assessments/{assessment_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    assessment_id: str,
):
    """WebSocket endpoint for live progress updates."""
    await manager.connect(assessment_id, websocket)
    stop_event = asyncio.Event()
    push_task = asyncio.create_task(
        push_progress_loop(assessment_id, stop_event=stop_event)
    )
    try:
        # Send initial connection confirmation
        await websocket.send_text(json.dumps({
            "type": "connected",
            "assessment_id": assessment_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

        # Keep connection open
        while True:
            try:
                data = await websocket.receive_text()
                # Echo any messages back (for testing)
                await websocket.send_text(json.dumps({
                    "type": "echo",
                    "received": data,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
            except WebSocketDisconnect:
                break
    finally:
        stop_event.set()
        push_task.cancel()
        try:
            await push_task
        except (asyncio.CancelledError, Exception):
            pass
        manager.disconnect(assessment_id, websocket)


# Error handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for unhandled errors."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if logger.level == logging.DEBUG else None,
        },
    )