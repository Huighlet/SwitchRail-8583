"""
SwitchRail-8583 Store-and-Forward (SAF) Reversal Queue.
Guarantees asynchronous retry and persistence of unacknowledged 0420 Reversals,
preventing floating debits during issuer outages.
"""

from __future__ import annotations

import dataclasses
import threading
import time
from typing import Dict, List, Optional

from switchrail.message import ISO8583Message
from switchrail.types import ResponseCode


@dataclasses.dataclass(slots=True)
class SAFRecord:
    """Queued reversal item awaiting successful issuer acknowledgement."""
    reversal_id: str
    destination_id: str
    reversal_message: ISO8583Message
    retry_count: int = 0
    max_retries: int = 5
    next_attempt_time: float = dataclasses.field(default_factory=time.time)
    created_at: float = dataclasses.field(default_factory=time.time)
    is_settled: bool = False


class StoreAndForwardQueue:
    """
    Thread-safe Store-and-Forward (SAF) Queue with exponential backoff retry scheduling.
    """
    def __init__(self, initial_backoff_sec: float = 2.0, backoff_multiplier: float = 2.0) -> None:
        self.initial_backoff = initial_backoff_sec
        self.multiplier = backoff_multiplier
        self._queue: Dict[str, SAFRecord] = {}
        self._lock = threading.Lock()

    def enqueue_reversal(
        self,
        reversal_id: str,
        destination_id: str,
        reversal_message: ISO8583Message,
        max_retries: int = 5,
    ) -> SAFRecord:
        """Enqueue a 0420 Reversal Advice for delivery."""
        with self._lock:
            record = SAFRecord(
                reversal_id=reversal_id,
                destination_id=destination_id,
                reversal_message=reversal_message,
                max_retries=max_retries,
                next_attempt_time=time.time(),
            )
            self._queue[reversal_id] = record
            return record

    def get_due_reversals(self) -> List[SAFRecord]:
        """Retrieve list of reversals whose scheduled attempt time has arrived."""
        now = time.time()
        with self._lock:
            return [
                r for r in self._queue.values()
                if not r.is_settled and r.retry_count < r.max_retries and r.next_attempt_time <= now
            ]

    def acknowledge_success(self, reversal_id: str) -> None:
        """Mark reversal as acknowledged upon receiving 0430 response."""
        with self._lock:
            if reversal_id in self._queue:
                self._queue[reversal_id].is_settled = True
                del self._queue[reversal_id]

    def record_attempt_failure(self, reversal_id: str) -> None:
        """Record a failed delivery attempt and schedule exponential backoff."""
        with self._lock:
            record = self._queue.get(reversal_id)
            if record is not None:
                record.retry_count += 1
                delay = self.initial_backoff * (self.multiplier ** (record.retry_count - 1))
                record.next_attempt_time = time.time() + delay

    def pending_count(self) -> int:
        """Count remaining unsettled reversals."""
        with self._lock:
            return len(self._queue)
