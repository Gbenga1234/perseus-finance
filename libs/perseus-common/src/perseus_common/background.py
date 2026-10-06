"""Lifecycle management for long-running background loops inside a service."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable

from perseus_common.logging import get_logger

log = get_logger(__name__)


class BackgroundWorkers:
    def __init__(self) -> None:
        self.stop_event = asyncio.Event()
        self._tasks: list[asyncio.Task[None]] = []

    def start(self, name: str, loop: Callable[[asyncio.Event], Awaitable[None]]) -> None:
        async def runner() -> None:
            try:
                await loop(self.stop_event)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("background_worker_crashed", worker=name)
                raise

        self._tasks.append(asyncio.create_task(runner(), name=name))
        log.info("background_worker_started", worker=name)

    async def stop(self, grace_seconds: float = 10.0) -> None:
        self.stop_event.set()
        if not self._tasks:
            return
        _done, pending = await asyncio.wait(self._tasks, timeout=grace_seconds)
        for task in pending:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)


async def sleep_or_stop(stop: asyncio.Event, seconds: float) -> None:
    """Sleep for ``seconds`` but wake immediately when ``stop`` is set."""
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(stop.wait(), timeout=seconds)
