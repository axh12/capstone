"""Offline regressions for the current deterministic simulation engine."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Digital Twin"))
from physics_engine import PhysicsEngine, PhysicsParams
from state_manager import StateValidator


class PhysicsEngineTests(unittest.TestCase):
    def test_same_seed_and_commands_produce_same_trajectory(self):
        first, second = PhysicsEngine(), PhysicsEngine()
        for tick in range(100):
            actions = {"p101": tick % 2, "mv101": 1, "p201": 1,
                       "p203": tick % 2, "mv201": 1, "p301": 1}
            first.apply_actions(actions)
            second.apply_actions(actions)
            self.assertEqual(first.step(), second.step())

    def test_inlet_valve_fills_t101_and_pump_drains_it(self):
        engine = PhysicsEngine()
        before = engine.snapshot()
        engine.apply_actions({"p101": 0, "mv101": 1})
        filling = engine.step()
        self.assertGreater(filling["LIT101"], before["LIT101"])
        self.assertGreater(filling["FIT101"], 0)
        self.assertEqual(filling["FIT201"], 0)
        engine.apply_actions({"p101": 1, "mv101": 0})
        draining = engine.step()
        self.assertLess(draining["LIT101"], filling["LIT101"])
        self.assertEqual(draining["FIT101"], 0)
        self.assertGreater(draining["FIT201"], 0)

    def test_stage1_level_obeys_flow_mass_balance(self):
        engine = PhysicsEngine(PhysicsParams(dt_seconds=10))
        start = engine.state.lit101
        engine.apply_actions({"p101": 1, "mv101": 1})
        engine.step()
        expected = start + (engine.state.fit101 - engine.state.fit201) * 10 * 1000 / (3600 * 2.0)
        self.assertAlmostEqual(engine.state.lit101, expected)

    def test_three_tank_rig_transfers_and_conserves_water(self):
        engine = PhysicsEngine(PhysicsParams(stage1_topology="three_tank_transfer", dt_seconds=30))
        start_volume = (engine.state.lit101 * engine.params.tank_area_m2['lit101']
                        + engine.state.lit201 * engine.params.tank_area_m2['lit201']
                        + engine.state.lit301 * engine.params.tank_area_m2['lit301'])
        third_level = engine.state.lit301
        filling = engine.step()
        self.assertGreater(filling['LIT101'], 500)
        self.assertLess(filling['LIT201'], 600)
        self.assertGreater(filling['FIT101'], 0)
        self.assertEqual(filling['FIT201'], 0)
        engine.apply_actions({'mv101': 0, 'p101': 1})
        draining = engine.step()
        self.assertLess(draining['LIT101'], filling['LIT101'])
        self.assertEqual(draining['LIT201'], filling['LIT201'])
        self.assertEqual(draining['FIT101'], 0)
        self.assertGreater(draining['FIT201'], 0)
        self.assertGreater(draining['LIT301'], third_level)
        ending_volume = (engine.state.lit101 * engine.params.tank_area_m2['lit101']
                         + engine.state.lit201 * engine.params.tank_area_m2['lit201']
                         + engine.state.lit301 * engine.params.tank_area_m2['lit301'])
        self.assertAlmostEqual(ending_volume, start_volume)

    def test_rig_auto_fill_stops_at_high_threshold_without_override(self):
        engine = PhysicsEngine(PhysicsParams(stage1_topology="three_tank_transfer", dt_seconds=300))
        engine.state.lit101 = 799.0
        engine.state.mv101 = 1
        state = engine.step()
        self.assertEqual(state['LIT101'], 800.0)
        self.assertEqual(state['mv101'], 0)
        state = engine.step()
        self.assertEqual(state['mv101'], 0)
        self.assertEqual(state['FIT101'], 0)

    def test_rig_uses_raw_ultrasonic_distance_for_pump_hysteresis(self):
        engine = PhysicsEngine(PhysicsParams(stage1_topology='three_tank_transfer'))
        engine.state.distance_cm = 9.0
        state = engine.step()
        self.assertEqual(state['mv101'], 1)
        self.assertLess(state['distance_cm'], 9.0)
        engine.state.distance_cm = 5.0
        self.assertEqual(engine.step()['mv101'], 1)
        engine.state.distance_cm = 2.0
        state = engine.step()
        self.assertEqual(state['mv101'], 0)
        self.assertEqual(state['FIT101'], 0.0)

    def test_dosing_changes_chemistry_in_expected_direction(self):
        engine = PhysicsEngine()
        before = engine.snapshot()
        engine.apply_actions({"p201": 1, "p203": 1})
        after = engine.step()
        self.assertGreater(after["AIT201_ORP"], before["AIT201_ORP"])
        self.assertLess(after["AIT202_pH"], before["AIT202_pH"])

    def test_long_run_respects_physical_bounds(self):
        engine = PhysicsEngine()
        validator = StateValidator()
        for phase in (0, 1):
            engine.apply_actions(dict.fromkeys(validator.ACTUATORS, phase))
            for tick in range(5000):
                state = engine.step()
                valid, reason = validator.validate(state)
                self.assertTrue(valid, f"phase={phase}, tick={tick}: {reason}")


if __name__ == "__main__":
    unittest.main()
