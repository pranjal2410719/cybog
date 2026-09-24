"""
cybog/queue/job_queue.py

BoundedJobQueue — asyncio.Queue wrapper with backpressure.
When full, enqueue() blocks (backpressure to upstream producer).
"""
from __future__ import annotations

import asyncio
from typing import Optional

from cybog.models.job import StageJob


class BoundedJobQueue:
    """Thread-safe bounded queue for StageJob objects."""

    def __init__(self, name: str, max_size: int = 100):
        self.name = name
        self._queue: asyncio.Queue[Optional[StageJob]] = asyncio.Queue(maxsize=max_size)
        self._max_size = max_size
        self._enqueued_total: int = 0
        self._dequeued_total: int = 0

    async def enqueue(self, job: StageJob, timeout: Optional[float] = None) -> None:
        """
        Enqueue a job. Blocks if queue is full (backpressure).
        Raises asyncio.TimeoutError if timeout expires.
        """
        if timeout is not None:
            await asyncio.wait_for(self._queue.put(job), timeout=timeout)
        else:
            await self._queue.put(job)
        self._enqueued_total += 1

    async def dequeue(self, timeout: Optional[float] = None) -> Optional[StageJob]:
        """
        Dequeue a job. Returns None sentinel when queue is shut down.
        Raises asyncio.TimeoutError if timeout expires.
        """
        if timeout is not None:
            job = await asyncio.wait_for(self._queue.get(), timeout=timeout)
        else:
            job = await self._queue.get()
        self._queue.task_done()
        self._dequeued_total += 1
        return job

    async def send_sentinel(self, count: int = 1) -> None:
        """Send N None sentinels to signal workers to shut down."""
        for _ in range(count):
            await self._queue.put(None)

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
