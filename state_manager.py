"""Authoritative, validated state owner for the Digital Twin."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Dict, Mapping, Tuple

from telemetry import build_state_change


@dataclass(frozen=True)
class StateTransition:
    version: int
    timestamp: str
    previous: Dict[str, Any]
    current: Dict[str, Any]
    changes: Dict[str, Any]


class StateValidator:
    """Reject invalid model/controller state before it becomes authoritative."""

    LIMITS = {
        "LIT101": (0.0, 1200.0), "LIT201": (0.0, 1000.0), "LIT301": (0.0, 1000.0),
        "distance_cm": (0.0, 1000.0),
        "AIT201_ORP": (0.0, 1000.0), "AIT202_pH": (0.0, 14.0),
    }
    ACTUATORS = {"p101", "mv101", "p201", "p203", "mv201", "p301"}

    def validate(self, state: Mapping[str, Any]) -> Tuple[bool, str]:
        for name, (low, high) in self.LIMITS.items():
            if name in state:
                try:
                    value = float(state[name])
                except (TypeError, ValueError):
                    return False, f"{name} is not numeric"
                if not low <= value <= high:
                    return False, f"{name}={value} outside [{low}, {high}]"
        for name in self.ACTUATORS:
            if name in state:
                try:
                    value = float(state[name])
                except (TypeError, ValueError, OverflowError):
                    return False, f"{name} must be 0 or 1"
                if value not in (0.0, 1.0):
                    return False, f"{name} must be 0 or 1"
        return True, "ok"


class StateManager:
    """Owns current/previous state and provides atomic validated transitions."""

    def __init__(self, initial_state: Mapping[str, Any] | None = None,
                 validator: StateValidator | None = None):
        self._lock = RLock()
        self._state: Dict[str, Any] = dict(initial_state or {})
        self._previous: Dict[str, Any] = {}
        self._version = 0
        self.validator = validator or StateValidator()

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return deepcopy(self._state)

    @property
    def version(self) -> int:
        with self._lock:
            return self._version

    def transition(self, candidate: Mapping[str, Any]) -> StateTransition:
        valid, reason = self.validator.validate(candidate)
        if not valid:
            raise ValueError(f"Rejected invalid Digital Twin state: {reason}")
        with self._lock:
            previous = deepcopy(self._state)
            current = deepcopy(dict(candidate))
            self._previous = previous
            self._state = current
            self._version += 1
            return StateTransition(
                version=self._version,
                timestamp=datetime.now(timezone.utc).isoformat(),
                previous=previous,
                current=deepcopy(current),
                changes=build_state_change(previous, current),
            )

    def apply_patch(self, patch: Mapping[str, Any]) -> StateTransition:
        with self._lock:
            candidate = self.snapshot()
            candidate.update(patch)
            return self.transition(candidate)
