"""
cybog/workers/pool.py

WorkerPool — asyncio.Semaphore-based pool with configurable concurrency.
Ensures at most N concurrent tool executions per stage.
"""
from __future__ import annotations

import asyncio

from cybog.logging_setup import get_logger

_log = get_logger("workers.pool")


class WorkerPool:
    """
    Semaphore-gated async worker pool.
    Usage:
        pool = WorkerPool("subfinder", max_workers=4)
        async with pool.acquire():
            result = await run_tool(...)
    """

    def __init__(self, name: str, max_workers: int):
        self.name = name
        self.max_workers = max_workers
        self._sem = asyncio.Semaphore(max_workers)
        self._active: int = 0
        self._completed: int = 0
        self._failed: int = 0

    def acquire(self) -> asyncio.Semaphore:
        """Context manager: acquire a worker slot."""
        return _SemaphoreContext(self)

    @property
    def active_count(self) -> int:
        return self._active

    @property
    def available_slots(self) -> int:
        return max(0, self.max_workers - self._active)

    @property
    def stats(self) -> dict:
        return {
            "pool": self.name,
            "max_workers": self.max_workers,
            "active": self._active,
            "available": self.available_slots,
            "completed": self._completed,
            "failed": self._failed,
        }


class _SemaphoreContext:
    """Internal context manager wrapping Semaphore for WorkerPool tracking."""

    def __init__(self, pool: WorkerPool):
        self._pool = pool

    async def __aenter__(self):
        await self._pool._sem.acquire()
        self._pool._active += 1
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._pool._active -= 1
        if exc_type is None:
            self._pool._completed += 1
        else:
            self._pool._failed += 1
        self._pool._sem.release()
        return False  # Never suppress exceptions
