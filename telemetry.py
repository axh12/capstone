"""Structured telemetry contract shared by the Digital Twin and detectors."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import json


@dataclass
class TelemetryEvent:
    """One immutable observation of network and process behavior."""

    event_id: str
    timestamp: str
    network: Dict[str, Any] = field(default_factory=dict)
    process: Dict[str, Any] = field(default_factory=dict)
    previous_process: Dict[str, Any] = field(default_factory=dict)
    state_change: Dict[str, Any] = field(default_factory=dict)
    network_statistics: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, event_id: str, **kwargs: Any) -> "TelemetryEvent":
        return cls(
            event_id=event_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            **kwargs,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def build_state_change(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """Return numeric/bool deltas without mutating either input mapping."""
    changes: Dict[str, Any] = {}
    for key, value in current.items():
        if key not in previous or previous[key] == value:
            continue
        old = previous[key]
        try:
            changes[key] = {"from": old, "to": value, "delta": float(value) - float(old)}
        except (TypeError, ValueError):
            changes[key] = {"from": old, "to": value}
    return changes
