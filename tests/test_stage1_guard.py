"""Independent tests for prediction isolation and explicit sensor tolerances."""
from types import SimpleNamespace
import unittest

from physics_engine import PhysicsEngine, PhysicsParams
from stage1_guard import Stage1Guard


class QuietDetector:
    def predict(self, state):
        return SimpleNamespace(ensemble_score=.1)


class Stage1GuardTests(unittest.TestCase):
    def test_predicts_overflow_without_mutating_authoritative_plant(self):
        twin=PhysicsEngine(PhysicsParams(stage1_topology='swat_stage1'))
        twin.state.lit101=1198.
        snapshot=twin.snapshot()
        rng=twin._rng.getstate()
        result=Stage1Guard().forecast(twin,'mv101',1,QuietDetector())
        self.assertGreater(result['forecast_spill_m3'],0)
        self.assertEqual(result['alternative_forecast_spill_m3'],0)
        self.assertEqual(twin.snapshot(),snapshot)
        self.assertEqual(twin._rng.getstate(),rng)
        self.assertEqual(twin.state.stage1_spill_m3,0)

    def test_safe_closing_is_not_an_overflow_risk(self):
        twin=PhysicsEngine(PhysicsParams(stage1_topology='swat_stage1'))
        twin.state.lit101=1198.
        result=Stage1Guard().forecast(twin,'mv101',0,QuietDetector())
        self.assertEqual(result['forecast_spill_m3'],0)
        self.assertGreater(result['alternative_forecast_spill_m3'],0)

    def test_declared_measurement_jitter_does_not_trigger_guard(self):
        issues=Stage1Guard().measurement_issues({'LIT101':740.,'FIT101':0.},
                                                {'LIT101':743.,'FIT101':.05})
        self.assertEqual(issues,{})

    def test_inconsistent_measurement_records_residual_not_an_attack_label(self):
        issues=Stage1Guard().measurement_issues({'LIT101':740.,'FIT101':0.},
                                                {'LIT101':700.,'FIT101':.2})
        self.assertEqual(issues['LIT101']['absolute_difference'],40.)
        self.assertEqual(issues['FIT101']['tolerance'],.1)

    def test_invalid_forecast_horizon_rejected(self):
        for value in (0,-1,301,float('nan')):
            with self.assertRaises(ValueError):
                Stage1Guard(forecast_seconds=value)
