"""
Abstract eBPF backend interface for LinuxNetLens.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Iterator, List, Optional

from linuxnetlens.events import Event
from linuxnetlens.flow import FlowFilter


class BpfBackend(ABC):
    """
    A backend produces a stream of typed ``Event`` objects.

    Backends MUST push flow filtering as deep as possible. For
    kernel-space backends that means emitting the filter as a
    guard clause in the probe body (see
    ``FlowFilter.as_bpftrace_guard()``) so we never pay for events
    outside the user's flow of interest.
    """

    name: str = "abstract"

    @abstractmethod
    def available(self) -> bool:
        """Return True if this backend can run on this host right now."""

    @abstractmethod
    def describe(self) -> str:
        """Return a short, human-readable descriptor for reports."""

    @abstractmethod
    def capture(
        self,
        duration: float = 10.0,
        flow_filter: Optional[FlowFilter] = None,
    ) -> List[Event]:
        """Capture events for ``duration`` seconds and return them."""

    def stream(
        self,
        duration: float = 10.0,
        flow_filter: Optional[FlowFilter] = None,
    ) -> Iterator[Event]:
        """
        Default streaming implementation defers to ``capture`` and
        yields.
        """

        for event in self.capture(duration=duration, flow_filter=flow_filter):
            yield event
