"""
cybog/queue/analyst_queue.py — Analyst Task Queue.

Bounded asyncio Queue for analyst validation tasks.
Each task carries a finding_id and analyst_id, and tracks validation status.
"""
from __future__ import annotations

import asyncio
from typing import Optional

from cybog.models.job import StageJob


class AnalystTask:
    """Represents a human analyst's validation task for a finding."""

    def __init__(
        self,
        task_id: str,
        finding_id: str,
        analyst_id: str,
        status: str = "PENDING",
        description: str = "",
    ):
        self.task_id = task_id
        self.finding_id = finding_id
        self.analyst_id = analyst_id
        self.status = status
        self.description = description
        self.created_at: str = ""
        self.completed_at: Optional[str] = None

    def model_dump(self) -> dict:
        return {
            "task_id": self.task_id,
            "finding_id": self.finding_id,
            "analyst_id": self.analyst_id,
            "status": self.status,
            "description": self.description,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }

    @classmethod
    def model_validate(cls, data: dict) -> "AnalystTask":
        task = cls(
            task_id=data.get("task_id", ""),
            finding_id=data.get("finding_id", ""),
            analyst_id=data.get("analyst_id", ""),
            status=data.get("status", "PENDING"),
            description=data.get("description", ""),
        )
        task.created_at = data.get("created_at", "")
        task.completed_at = data.get("completed_at")
        return task


class BoundedAnalystQueue:
    """Thread-safe bounded queue for AnalystTask objects.

    When full, enqueue() blocks (backpressure to upstream producer).
    """

    def __init__(self, name: str, max_size: int = 100):
        self.name = name
        self._queue: asyncio.Queue[AnalystTask] = asyncio.Queue(maxsize=max_size)
        self._max_size = max_size
        self._enqueued_total: int = 0
        self._dequeued_total: int = 0

    async def enqueue(self, task: AnalystTask, timeout: Optional[float] = None) -> None:
        """Enqueue an analyst task. Blocks if queue is full (backpressure)."""
        if timeout is not None:
            await asyncio.wait_for(self._queue.put(task), timeout=timeout)
        else:
            await self._queue.put(task)
        self._enqueued_total += 1

    async def dequeue(self, timeout: Optional[float] = None) -> Optional[AnalystTask]:
        """Dequeue an analyst task. Returns None sentinel when queue is shut down."""
        if timeout is not None:
            task = await asyncio.wait_for(self._queue.get(), timeout=timeout)
        else:
            task = await self._queue.get()
        self._queue.task_done()
        self._dequeued_total += 1
        return task

    async def send_sentinel(self, count: int = 1) -> None:
        """Send N None sentinels to signal workers to shut down."""
        for _ in range(count):
            await self._queue.put(None)  # type: ignore[arg-type]

    def size(self) -> int:
        return self._queue.qsize()

    def is_full(self) -> bool:
        return self._queue.full()

    def is_empty(self) -> bool:
        return self._queue.empty()

    @property
    def max_size(self) -> int:
        return self._max_size

    @property
    def stats(self) -> dict:
        return {
            "name": self.name,
            "current_size": self.size(),
            "max_size": self._max_size,
            "enqueued_total": self._enqueued_total,
            "dequeued_total": self._dequeued_total,
        }