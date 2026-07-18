import asyncio
from bxp_secretsonar.core.models import Candidate


class PriorityAsyncQueue:
    def __init__(self, maxsize: int = 1000):
        self._queue: asyncio.PriorityQueue[tuple[int, float, Candidate]] = asyncio.PriorityQueue(maxsize=maxsize)
        self._counter = 0
        self._lock = asyncio.Lock()

    async def put(self, candidate: Candidate) -> None:
        async with self._lock:
            self._counter += 1
            await self._queue.put((candidate.priority, self._counter, candidate))

    async def get(self) -> Candidate:
        _, _, candidate = await self._queue.get()
        return candidate

    def task_done(self) -> None:
        self._queue.task_done()

    @property
    def size(self) -> int:
        return self._queue.qsize()

    async def shutdown(self) -> None:
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except asyncio.QueueEmpty:
                break
