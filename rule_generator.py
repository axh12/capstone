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
        rules = self.manager.rules_from_signature(signature)
        now = datetime.now(timezone.utc).isoformat()
        self.candidates = [CandidateRule(rule, now) for rule in rules]
        return list(self.candidates)

    def activate(self, candidate: CandidateRule) -> Dict:
        result = self.manager.export_signature({
            "modbus_commands": [],
        }) if False else self.manager.write()
        self.candidates = [
            CandidateRule(item.rule, item.created_at, item.rule == candidate.rule)
            for item in self.candidates
        ]
        return {"path": str(result), "rule": candidate.rule, "active": True}

    def discard(self) -> None:
        for candidate in self.candidates:
            self.manager._rules.pop(candidate.rule, None)
            self.manager._rule_expiry.pop(candidate.rule, None)
        self.candidates = []
