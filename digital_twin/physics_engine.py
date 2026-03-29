"""
Standalone SWaT-style physics engine.

This module keeps plant state and updates it using simple water-treatment physics.
It is intentionally lightweight so it can be reused by any controller (rule-based or LLM-based).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict
import random


@dataclass
class PlantState:
    # Tank levels (mm)
    lit101: float = 500.0
    lit201: float = 600.0
    lit301: float = 800.0

    # Flows (m3/h)
    fit101: float = 0.0
    fit201: float = 0.0
    fit301: float = 0.0

    # Chemistry
    ait201_orp: float = 250.0
    ait202_ph: float = 7.2

    # Actuators (0/1)
    p101: int = 0
    mv101: int = 0
    p201: int = 0
    p203: int = 0
    mv201: int = 0
    p301: int = 0


@dataclass
class PhysicsParams:
    dt_seconds: float = 1.0
    tank_area_m2: Dict[str, float] = field(
        default_factory=lambda: {
            "lit101": 2.0,
            "lit201": 1.8,
            "lit301": 1.5,
        }
    )
    max_level_mm: Dict[str, float] = field(
        default_factory=lambda: {
            "lit101": 1200.0,
            "lit201": 1000.0,
            "lit301": 1000.0,
        }
    )


class PhysicsEngine:
    def __init__(self, params: PhysicsParams | None = None):
        self.params = params or PhysicsParams()
        self.state = PlantState()

    def apply_actions(self, actions: Dict[str, int]) -> None:
        """Apply binary actuator commands from a controller."""
        for key, value in actions.items():
            if hasattr(self.state, key):
                setattr(self.state, key, 1 if int(value) else 0)

    def step(self) -> Dict[str, float]:
        """Advance the process by one physics tick."""
        s = self.state
        dt = self.params.dt_seconds

        def noise(scale: float) -> float:
            return random.uniform(-scale, scale)

        def level_delta_mm(flow_m3h: float, tank_key: str) -> float:
            volume = (flow_m3h / 3600.0) * dt
            return (volume * 1000.0) / self.params.tank_area_m2[tank_key]

        def clamp_level(tank_key: str, level: float) -> float:
            return max(0.0, min(self.params.max_level_mm[tank_key], level))

        # Stage 1: raw water intake
        if s.p101 == 1:
            s.fit101 = 2.5 + noise(0.05)
        else:
            s.fit101 = 0.0

        inflow_101 = level_delta_mm(s.fit101, "lit101")
        outflow_101_rate = 2.3 + noise(0.05) if s.mv101 == 1 and s.lit101 > 50 else 0.0
        outflow_101 = level_delta_mm(outflow_101_rate, "lit101")
        s.lit101 = clamp_level("lit101", s.lit101 + inflow_101 - outflow_101)

        # Stage 2: dosing tank receives water from stage 1
        s.fit201 = max(0.0, outflow_101_rate)
        inflow_201 = level_delta_mm(s.fit201, "lit201")
        outflow_201_rate = 2.1 + noise(0.05) if s.mv201 == 1 and s.lit201 > 30 else 0.0
        outflow_201 = level_delta_mm(outflow_201_rate, "lit201")
        s.lit201 = clamp_level("lit201", s.lit201 + inflow_201 - outflow_201)

        # Chemistry effects in stage 2
        if s.p201 == 1:
            s.ait201_orp = min(600.0, s.ait201_orp + 0.8 + noise(0.2))
        else:
            s.ait201_orp = max(100.0, s.ait201_orp - 0.3)

        if s.p203 == 1:
            s.ait202_ph = max(5.0, s.ait202_ph - 0.02 + noise(0.005))
        else:
            s.ait202_ph = min(8.5, s.ait202_ph + 0.01)

        # Stage 3: UF feed tank
        s.fit301 = max(0.0, outflow_201_rate)
        inflow_301 = level_delta_mm(s.fit301, "lit301")
        consumption_301_rate = 2.0 + noise(0.04) if s.p301 == 1 and s.lit301 > 20 else 0.0
        consumption_301 = level_delta_mm(consumption_301_rate, "lit301")
        s.lit301 = clamp_level("lit301", s.lit301 + inflow_301 - consumption_301)

        return self.snapshot()

    def snapshot(self) -> Dict[str, float]:
        s = self.state
        return {
            "LIT101": round(s.lit101, 2),
            "LIT201": round(s.lit201, 2),
            "LIT301": round(s.lit301, 2),
            "FIT101": round(s.fit101, 3),
            "FIT201": round(s.fit201, 3),
            "FIT301": round(s.fit301, 3),
            "AIT201_ORP": round(s.ait201_orp, 2),
            "AIT202_pH": round(s.ait202_ph, 3),
            "p101": s.p101,
            "mv101": s.mv101,
            "p201": s.p201,
            "p203": s.p203,
            "mv201": s.mv201,
            "p301": s.p301,
        }
