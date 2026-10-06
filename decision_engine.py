"""Anomaly-gated enforcement decision contract."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class DecisionResult:
    decision: Decision
    reason: str
    signature: Optional[Dict[str, Any]] = None
    rule: Optional[str] = None


class DecisionEngine:
    """Only anomalous behavior can activate a candidate rule."""

    def decide(self, anomaly_result: Any, signature: Optional[Dict[str, Any]],
               candidate_rule: Optional[str] = None) -> DecisionResult:
        if bool(getattr(anomaly_result, "is_anomaly", False)):
            return DecisionResult(Decision.BLOCK, "anomaly detected", signature, candidate_rule)
        return DecisionResult(Decision.ALLOW, "normal traffic; candidate discarded", None, None)
