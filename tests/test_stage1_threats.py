"""Independent overflow oracle and telemetry-falsification boundary checks."""
import unittest

from mock_scada import MockScadaServer
from mock_stage1_telemetry import MockStage1TelemetrySource
from physics_engine import PhysicsEngine, PhysicsParams


class Stage1ThreatTests(unittest.TestCase):
    def test_full_tank_spills_instead_of_silently_stopping_inlet(self):
        twin = PhysicsEngine(PhysicsParams(stage1_topology='swat_stage1', flow_noise_m3h=0))
        twin.state.lit101 = 1200.
        twin.apply_actions({'mv101': 1})
        state = twin.step()
        self.assertEqual(state['LIT101'], 1200.)
        self.assertGreater(state['FIT101'], 0.)
        self.assertAlmostEqual(twin.state.stage1_spill_m3,
                               twin.params.stage1_inlet_flow_m3h / 3600.)
        self.assertNotIn('stage1_spill_m3', state)

    def test_filling_conserves_water_across_storage_and_overflow(self):
        twin = PhysicsEngine(PhysicsParams(stage1_topology='swat_stage1', flow_noise_m3h=0))
        twin.state.lit101 = 1199.9
        twin.apply_actions({'mv101': 1})
        twin.step()
        stored = .1 * twin.params.tank_area_m2['lit101'] / 1000.
        self.assertAlmostEqual(stored + twin.state.stage1_spill_m3,
                               twin.params.stage1_inlet_flow_m3h / 3600.)
        before = twin.state.stage1_spill_m3
        twin.apply_actions({'mv101': 0})
        twin.step()
        self.assertEqual(twin.state.stage1_spill_m3, before)

    def test_forged_reading_does_not_change_independent_plant(self):
        with MockScadaServer(('127.0.0.1', 0)) as scada:
            scada.initialize_plant(PhysicsEngine(PhysicsParams(stage1_topology='swat_stage1')))
            before = scada.plant.snapshot()
            source = MockStage1TelemetrySource(scada, {'LIT101': 100., 'FIT101': 30.})
            self.assertEqual(source.read_state(), {'LIT101': 100., 'FIT101': 30.})
            self.assertEqual(scada.plant.snapshot(), before)

    def test_unmodified_connector_reads_real_mock_measurements(self):
        with MockScadaServer(('127.0.0.1', 0)) as scada:
            scada.initialize_plant(PhysicsEngine(PhysicsParams(stage1_topology='swat_stage1')))
            source = MockStage1TelemetrySource(scada)
            self.assertEqual(source.read_state(), {'LIT101': 500., 'FIT101': 0.})

    def test_spoof_adapter_cannot_override_actuators_or_other_stages(self):
        for name in ('p101', 'LIT301', 'AIT202_pH'):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    MockStage1TelemetrySource(None, {name: 1})
