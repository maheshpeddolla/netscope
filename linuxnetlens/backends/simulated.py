"""
JSON-replay backend for LinuxNetLens.

Reads events from either:

    - a JSON file path (``replay_path``), or
    - an in-memory iterable of pre-serialised event dicts.

Enables Windows/CI/demos with no eBPF stack.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Optional, Union

from linuxnetlens.backends.base import BpfBackend
from linuxnetlens.events import Event, event_from_dict
from linuxnetlens.flow import FlowFilter


class SimulatedBackend(BpfBackend):
    """
    A backend that replays a canned JSON event stream.

    JSON format::

        {
            "events": [
                { "kind": "tcp_state", "timestamp": ..., ... },
                ...
            ]
        }

    A top-level list of event dicts is also accepted.
    """

    name = "simulated"

    def __init__(
        self,
        *,
        replay_path: Optional[Union[str, Path]] = None,
        events: Optional[Iterable[Union[dict, Event]]] = None,
    ):
        self._replay_path = Path(replay_path) if replay_path else None
        self._events: List[Event] = []

        if events is not None:
            self._load_iterable(events)
        elif self._replay_path is not None:
            self._load_file(self._replay_path)

    # ------------------------------------------------------------------
    # BpfBackend interface
    # ------------------------------------------------------------------

    def available(self) -> bool:
        return True

    def describe(self) -> str:

        if self._replay_path is not None:
            return f"simulated (replay: {self._replay_path.name})"
        if self._events:
            return f"simulated (in-memory, {len(self._events)} events)"
        return "simulated (empty)"

    def capture(
        self,
        duration: float = 10.0,
        flow_filter: Optional[FlowFilter] = None,
    ) -> List[Event]:

        if flow_filter is None or flow_filter.is_broad():
            return list(self._events)

        return [e for e in self._events if self._matches(e, flow_filter)]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _matches(event: Event, flow_filter: FlowFilter) -> bool:

        flow = getattr(event, "flow", None)

        if flow is None:
            return True  # keep unattributed events; ledger routes them

        return flow_filter.matches(flow)

    def _load_iterable(
        self, events: Iterable[Union[dict, Event]]
    ) -> None:

        for item in events:

            if isinstance(item, Event):
                self._events.append(item)
                continue

            if isinstance(item, dict):
                self._events.append(event_from_dict(item))
                continue

            raise TypeError(
                f"SimulatedBackend cannot ingest event of type {type(item)!r}"
            )

    def _load_file(self, path: Path) -> None:

        if not path.exists():
            raise FileNotFoundError(f"replay file not found: {path}")

        with path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)

        if isinstance(payload, dict):
            events = payload.get("events", [])
        elif isinstance(payload, list):
            events = payload
        else:
            raise ValueError(
                f"replay file {path} must contain a list or "
                f"an object with an 'events' key"
            )

        self._load_iterable(events)
