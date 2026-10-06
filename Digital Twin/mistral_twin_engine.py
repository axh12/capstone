"""
Mistral Twin Engine (Ollama-backed controller + physics loop).

This file uses a local Ollama model (default: mistral) as the control brain,
then applies those commands to the physics engine each cycle.
"""

from __future__ import annotations

import json
import time
import os
import sys
from copy import deepcopy
from typing import Dict, Any

import requests

from physics_engine import PhysicsEngine
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from state_manager import StateValidator


class OllamaMistralController:
    def __init__(
        self,
        model: str = "mistral",
        base_url: str = "http://localhost:11434",
        timeout_seconds: int = 15,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def is_available(self) -> bool:
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=2)
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def propose_actions(self, state: Dict[str, float]) -> Dict[str, int]:
        """
        Ask Mistral to produce 0/1 actuator commands in strict JSON.
        Falls back to safe local control if parsing/network fails.
        """
        prompt = (
            "You are controlling a water treatment digital twin. "
            "Return only a JSON object with integer 0 or 1 for keys: "
            "p101,mv101,p201,p203,mv201,p301. "
            "Goals: keep LIT101 in [450,900], LIT201 in [500,850], LIT301 in [650,900], "
            "keep AIT202_pH in [6.8,7.6], keep AIT201_ORP in [220,420]. "
            "Current state: "
            + json.dumps(state)
        )

        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }

        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout_seconds,
            )
            resp.raise_for_status()
            raw_text = resp.json().get("response", "{}")
            actions = self._parse_actions(raw_text)
            return self._sanitize_actions(actions)
        except (requests.RequestException, ValueError, KeyError, TypeError):
            return self._fallback_actions(state)

    def _parse_actions(self, text: str) -> Dict[str, Any]:
        text = text.strip()
        if not text:
            return {}

        # Allow extra text around JSON if model does not fully obey.
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return {}

        return json.loads(text[start : end + 1])

    def _sanitize_actions(self, actions: Dict[str, Any]) -> Dict[str, int]:
        valid_keys = ["p101", "mv101", "p201", "p203", "mv201", "p301"]
        safe = {}
        for key in valid_keys:
            value = actions.get(key, 0)
            safe[key] = 1 if int(value) else 0
        return safe

    def _fallback_actions(self, state: Dict[str, float]) -> Dict[str, int]:
        # Local rule-based backup keeps plant stable if Ollama fails.
        return {
            "p101": 1 if state["LIT101"] < 700 else 0,
            "mv101": 1 if state["LIT101"] > 520 else 0,
            "p201": 1 if state["AIT201_ORP"] < 280 else 0,
            "p203": 1 if state["AIT202_pH"] > 7.4 else 0,
            "mv201": 1 if state["LIT201"] > 560 else 0,
            "p301": 1 if state["LIT301"] > 680 else 0,
        }


class MistralTwinEngine:
    def __init__(self, model: str = "mistral"):
        self.physics = PhysicsEngine()
        self.controller = OllamaMistralController(model=model)
        self.validator = StateValidator()

    def run(self, steps: int = 60, step_sleep_seconds: float = 1.0) -> None:
        available = self.controller.is_available()
        print(f"Ollama available: {available}")
        print(f"Controller model: {self.controller.model}")
        print("Starting twin loop...\n")

        for tick in range(1, steps + 1):
            state = self.physics.snapshot()
            previous_state = deepcopy(self.physics.state)
            actions = self.controller.propose_actions(state)
            self.physics.apply_actions(actions)
            new_state = self.physics.step()
            valid, reason = self.validator.validate(new_state)
            if not valid:
                # Reject an invalid model transition and restore the prior
                # snapshot rather than allowing unsafe simulated state.
                self.physics.state = previous_state
                print(f"Rejected invalid Mistral state: {reason}; using fallback state")
                new_state = self.physics.snapshot()

            print(
                f"Tick {tick:03d} | "
                f"Actions={actions} | "
                f"LIT101={new_state['LIT101']:.1f} "
                f"LIT201={new_state['LIT201']:.1f} "
                f"LIT301={new_state['LIT301']:.1f} "
                f"pH={new_state['AIT202_pH']:.2f} "
                f"ORP={new_state['AIT201_ORP']:.1f}"
            )

            time.sleep(step_sleep_seconds)


if __name__ == "__main__":
    # Requires: ollama serve, then ollama pull mistral
    twin = MistralTwinEngine(model="mistral")
    twin.run(steps=120, step_sleep_seconds=1.0)
