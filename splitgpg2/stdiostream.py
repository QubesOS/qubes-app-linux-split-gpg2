#
# based on asyncio library:
# Copyright (C) 2001 Python Software Foundation
#
# Copyright (C) 2024 Marek Marczykowski-Górecki
#                               <marmarek@invisiblethingslab.com>
#

import collections
from asyncio import protocols, events, Future
from typing import Optional, Any

class StdoutWriterProtocol(protocols.Protocol):
    """Reusable flow control logic for StreamWriter.drain().
    This implements the protocol methods pause_writing(),
    resume_writing() and connection_lost().  If the subclass overrides
    these it must call the super methods.
    StreamWriter.drain() must wait for _drain_helper() coroutine.
    """

    def __init__(self, loop: Optional[events.AbstractEventLoop] = None) -> None:
        if loop is None:
            self._loop = events.get_event_loop()
        else:
            self._loop = loop
        self._paused = False
        self._drain_waiters: collections.deque[Future[None]] = \
            collections.deque()
        self._connection_lost = False
        self._closed = self._loop.create_future()

    def pause_writing(self) -> None:
        assert not self._paused
        self._paused = True

    def resume_writing(self) -> None:
        assert self._paused
        self._paused = False

        for waiter in self._drain_waiters:
            if not waiter.done():
                waiter.set_result(None)

    def connection_lost(self, exc: Optional[BaseException]) -> None:
        self._connection_lost = True

        # Wake up the writer(s) if currently paused.
        if self._paused:
            for waiter in self._drain_waiters:
                if not waiter.done():
                    if exc is None:
                        waiter.set_result(None)
                    else:
                        waiter.set_exception(exc)

        if not self._closed.done():
            if exc is None:
                self._closed.set_result(None)
            else:
                self._closed.set_exception(exc)

    async def _drain_helper(self) -> None:
        if self._connection_lost:
            raise ConnectionResetError('Connection lost')
        if not self._paused:
            return
        waiter = self._loop.create_future()
        self._drain_waiters.append(waiter)
        try:
            await waiter
        finally:
            self._drain_waiters.remove(waiter)

    # pylint: disable=unused-argument
    def _get_close_waiter(self, stream: Any) -> Future[None]:
        return self._closed
