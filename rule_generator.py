"""Candidate-rule lifecycle wrapper around SnortRuleManager."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

from snort_integration import SnortRuleManager


@dataclass(frozen=True)
class CandidateRule:
    rule: str
    created_at: str
    active: bool = False


class RuleGenerator:
    def __init__(self, manager: SnortRuleManager):
        self.manager = manager
        self.candidates: List[CandidateRule] = []

    def generate(self, signature: Dict) -> List[CandidateRule]:
        # Generate in an isolated manager: pending candidates must not enter
        # the persisted active set before an explicit activation.
        pending = SnortRuleManager(blocking=self.manager.blocking,
                                   allow_ip_fallback=self.manager.allow_ip_fallback)
        rules = pending.rules_from_signature(signature)
        now = datetime.now(timezone.utc).isoformat()
        self.candidates = [CandidateRule(rule, now) for rule in rules]
        return list(self.candidates)

    def activate(self, candidate: CandidateRule) -> Dict:
        if candidate not in self.candidates:
            raise ValueError("Unknown candidate rule")
        from datetime import timedelta
        self.manager._rules[candidate.rule] = candidate.rule
        self.manager._rule_expiry[candidate.rule] = datetime.now(timezone.utc) + timedelta(seconds=self.manager.expiration_seconds)
        result = self.manager.write()
        self.candidates = [
            CandidateRule(item.rule, item.created_at, item.active or item.rule == candidate.rule)
            for item in self.candidates
        ]
        return {"path": str(result), "rule": candidate.rule, "active": True}

    def discard(self) -> None:
        # Pending candidates are isolated from the active manager. Discarding
        # a duplicate must never remove a rule approved in an earlier batch.
        self.candidates = []
