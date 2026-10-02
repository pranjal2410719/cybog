"""
cybog/logging_setup.py

Structured JSON logger. Every record carries:
    assessment_id, target_id, stage, job_id, tool
"""
from __future__ import annotations
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Optional


class JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "msg": record.getMessage(),
            "module": record.module,
            "assessment_id": getattr(record, "assessment_id", None),
            "target_id": getattr(record, "target_id", None),
            "stage": getattr(record, "stage", None),
            "job_id": getattr(record, "job_id", None),
            "tool": getattr(record, "tool", None),
        }
        if record.exc_info:
            log_obj["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)


def setup_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Configure root logger. Call once at startup."""
    root = logging.getLogger("cybog")
    if root.handlers:
        return
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
        )
    root.addHandler(handler)


def get_logger(name: str = "cybog") -> logging.Logger:
    return logging.getLogger(f"cybog.{name}" if not name.startswith("cybog") else name)


class ContextLogger:
    """Logger with pre-bound context fields."""

    def __init__(
        self,
        name: str,
        assessment_id: Optional[str] = None,
        target_id: Optional[str] = None,
        stage: Optional[str] = None,
        job_id: Optional[str] = None,
        tool: Optional[str] = None,
    ):
        self._logger = get_logger(name)
        self._extra = {
            "assessment_id": assessment_id,
            "target_id": target_id,
            "stage": stage,
            "job_id": job_id,
            "tool": tool,
        }

    def _log(self, level: int, msg: str, **extra) -> None:
        merged = {**self._extra, **extra}
        self._logger.log(level, msg, extra=merged)

    def info(self, msg: str, **kw) -> None:
        self._log(logging.INFO, msg, **kw)

    def warning(self, msg: str, **kw) -> None:
        self._log(logging.WARNING, msg, **kw)

    def error(self, msg: str, **kw) -> None:
        self._log(logging.ERROR, msg, **kw)

    def debug(self, msg: str, **kw) -> None:
        self._log(logging.DEBUG, msg, **kw)

    def bind(self, **kw) -> "ContextLogger":
        """Return a new logger with additional bound fields."""
        new = ContextLogger(self._logger.name)
        new._extra = {**self._extra, **kw}
        return new
