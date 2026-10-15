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
    # Raw top-mounted ultrasonic reading on the physical rig, when connected.
    distance_cm: float | None = None

    # Flows (m3/h). On the rig, FIT201 is measured on box 2 -> box 3;
    # FIT101 is only an estimated box 1 -> box 2 flow.
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
    random_seed: int = 0
    # 'swat' preserves the research simulator; 'three_tank_transfer' models
    # box 1 -> box 2 -> box 3 in the physical rig.
    stage1_topology: str = "swat"
    stage1_auto_low_level_mm: float = 500.0
    stage1_auto_high_level_mm: float = 800.0
    # Nominal flows from the local normal SWaT trace, in m3/h. Replace these
    # and tank_area_m2 with measurements from the physical Stage 1 rig.
    stage1_inlet_flow_m3h: float = 4.37
    stage1_pump_flow_m3h: float = 2.33
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
        if self.params.stage1_topology not in ("swat", "three_tank_transfer"):
            raise ValueError("Unknown Stage 1 topology")
        if self.params.dt_seconds <= 0 or any(area <= 0 for area in self.params.tank_area_m2.values()):
            raise ValueError("Physics timestep and tank areas must be positive")
        if (self.params.stage1_topology == "three_tank_transfer" and not
                0 <= self.params.stage1_auto_low_level_mm < self.params.stage1_auto_high_level_mm
                <= self.params.max_level_mm["lit101"]):
            raise ValueError("Invalid box-2 automatic fill thresholds")
        self.state = PlantState()
        self._rng = random.Random(self.params.random_seed)
        self._inlet_override_active = False

    def apply_actions(self, actions: Dict[str, int]) -> None:
        """Apply binary actuator commands from a controller."""
        for key, value in actions.items():
            if hasattr(self.state, key):
                setattr(self.state, key, 1 if int(value) else 0)
                if key == "mv101" and self.params.stage1_topology == "three_tank_transfer":
                    self._inlet_override_active = True

    def release_inlet_override(self) -> None:
        """Return the rig simulation's inlet pump to level-based control."""
        self._inlet_override_active = False

    def step(self) -> Dict[str, float]:
        """Advance the process by one physics tick."""
        s = self.state
        dt = self.params.dt_seconds

        def noise(scale: float) -> float:
            return self._rng.uniform(-scale, scale)

        def level_delta_mm(flow_m3h: float, tank_key: str) -> float:
            volume = (flow_m3h / 3600.0) * dt
            return (volume * 1000.0) / self.params.tank_area_m2[tank_key]

        def clamp_level(tank_key: str, level: float) -> float:
            return max(0.0, min(self.params.max_level_mm[tank_key], level))

        if self.params.stage1_topology == "three_tank_transfer":
            # Box 1 (LIT201) supplies box 2 (LIT101); the manual outlet pump
            # moves water from box 2 into box 3 (LIT301). FIT101 is estimated;
            # FIT201 is the location of the rig's single physical flow meter.
            observed_distance = s.distance_cm
            level_before = s.lit101
            if not self._inlet_override_active:
                if observed_distance is not None:
                    if observed_distance >= 8:
                        s.mv101 = 1
                    elif observed_distance <= 2:
                        s.mv101 = 0
                elif s.lit101 <= self.params.stage1_auto_low_level_mm:
                    s.mv101 = 1
                elif s.lit101 >= self.params.stage1_auto_high_level_mm:
                    s.mv101 = 0

            def transfer(source: str, destination: str, nominal_m3h: float,
                         destination_limit_mm: float | None = None) -> float:
                source_area = self.params.tank_area_m2[source]
                destination_area = self.params.tank_area_m2[destination]
                available_m3 = getattr(s, source) * source_area / 1000.0
                limit = (self.params.max_level_mm[destination] if destination_limit_mm is None
                         else min(self.params.max_level_mm[destination], destination_limit_mm))
                headroom_m3 = (limit - getattr(s, destination)) * destination_area / 1000.0
                volume_m3 = min(nominal_m3h * dt / 3600.0, available_m3, headroom_m3)
                volume_m3 = max(0.0, volume_m3)
                setattr(s, source, getattr(s, source) - volume_m3 * 1000.0 / source_area)
                setattr(s, destination, getattr(s, destination) + volume_m3 * 1000.0 / destination_area)
                return volume_m3 * 3600.0 / dt

            s.fit101 = 0.0
            if s.mv101:
                if self._inlet_override_active:
                    limit = None
                elif observed_distance is not None:
                    limit = s.lit101 + max(0.0, observed_distance - 2) * 10
                else:
                    limit = self.params.stage1_auto_high_level_mm
                s.fit101 = transfer("lit201", "lit101", self.params.stage1_inlet_flow_m3h,
                                    limit)
            s.fit201 = (transfer("lit101", "lit301", self.params.stage1_pump_flow_m3h)
                        if s.p101 else 0.0)
            if observed_distance is not None:
                # Preserve the sensor's raw measurement as the starting point;
                # this tick's distance change is a provisional simulation.
                s.distance_cm = max(0.0, observed_distance - (s.lit101 - level_before) / 10)
            if not self._inlet_override_active:
                if s.distance_cm is not None and s.distance_cm <= 2:
                    s.mv101 = 0
                elif s.distance_cm is None and s.lit101 >= self.params.stage1_auto_high_level_mm:
                    s.mv101 = 0
            s.fit301 = 0.0
            return self.snapshot()

        # Stage 1: MV101/FIT101 fill T101; P101 drains it to Stage 2.
        # MV101 may map to an inlet pump on a reduced physical rig.
        s.fit101 = (max(0.0, self.params.stage1_inlet_flow_m3h + noise(0.05))
                    if s.mv101 == 1 and s.lit101 < self.params.max_level_mm["lit101"]
                    else 0.0)
        inflow_101 = level_delta_mm(s.fit101, "lit101")
        outflow_101_rate = (max(0.0, self.params.stage1_pump_flow_m3h + noise(0.05))
                            if s.p101 == 1 and s.lit101 > 50 else 0.0)
        outflow_101 = level_delta_mm(outflow_101_rate, "lit101")
        s.lit101 = clamp_level("lit101", s.lit101 + inflow_101 - outflow_101)

        # Stage 2 receives the estimated Stage 1 outlet flow.
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
        state = {
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
        if s.distance_cm is not None:
            state["distance_cm"] = round(s.distance_cm, 3)
        return state
