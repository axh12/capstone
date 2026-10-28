"""Stage-1-only provenance, physics, register scope and downstream isolation."""
import json
from copy import deepcopy
from pathlib import Path
import struct
import tempfile
import unittest

import pandas as pd

from swat_mock_profile import fit_profile, load_profile, PhysicsParams
from physics_engine import PhysicsEngine
from mock_scada import MockScadaServer
from modbus_gateway import ModbusGateway
from orchestrator import IntegrationOrchestrator
from research_state_profile import initialize_twin_from_training_reference


def frame(address, value=1, function=6):
    return struct.pack('>HHHBBHH', 1, 0, 6, 1, function, address, value)


class SwatMockTests(unittest.TestCase):
    def data(self):
        return pd.DataFrame({
            't_stamp': pd.date_range('2026-01-01', periods=200, freq='s'),
            'y_true': [0] * 180 + [1] * 20,
            'LIT101.Pv': [600 + i * .9 for i in range(60)]
                          + [654 - i * .45 for i in range(60)] + [600.] * 80,
            'MV101.Status': [2] * 60 + [1] * 140,
            'P101.Status': [1] * 60 + [2] * 140,
            'P102.Status': [1] * 200,
            'FIT101.Pv': [4.37] * 60 + [0.] * 140,
        })

    def test_calibration_excludes_later_rows_and_training_attacks(self):
        data = self.data()
        data.loc[0, 'y_true'] = 1
        expected = fit_profile(data)
        data.loc[120:, ['FIT101.Pv', 'LIT101.Pv']] = 9999.
        data.loc[0, ['FIT101.Pv', 'LIT101.Pv']] = 9999.
        self.assertEqual(fit_profile(data), expected)
        self.assertEqual(expected['physics']['stage1_inlet_flow_m3h'], 4.37)
        self.assertEqual(set(expected['normal_reference']), {'LIT101', 'FIT101'})

    def test_stage1_mass_balance_and_no_other_stage_state(self):
        twin = PhysicsEngine(PhysicsParams(stage1_topology='swat_stage1', flow_noise_m3h=.001))
        twin.apply_actions({'mv101': 1, 'p101': 1, 'p102': 1})
        before = twin.state.lit101
        state = twin.step()
        expected = before + (twin.state.fit101 - 2 * twin.params.stage1_pump_flow_m3h) * 1000 / (3600 * 2)
        self.assertAlmostEqual(twin.state.lit101, expected)
        self.assertEqual(set(state), {'LIT101', 'FIT101', 'p101', 'p102', 'mv101'})
        self.assertEqual(twin.state.lit301, 800.)
        self.assertEqual(twin.state.ait202_ph, 7.2)

    def test_reference_initializes_only_stage1(self):
        twin = PhysicsEngine(PhysicsParams(stage1_topology='swat_stage1'))
        initialize_twin_from_training_reference(twin, {'LIT101': 740., 'FIT101': 0.})
        self.assertEqual(twin.snapshot(), {'LIT101': 740., 'FIT101': 0., 'p101': 0, 'p102': 0, 'mv101': 0})
        with self.assertRaises(ValueError):
            initialize_twin_from_training_reference(twin, {'LIT101': 740., 'FIT101': 0., 'LIT301': 929.})

    def test_mock_independence_precision_and_stage1_safety(self):
        twin = PhysicsEngine(PhysicsParams(stage1_topology='swat_stage1'))
        with MockScadaServer(('127.0.0.1', 0)) as mock:
            mock.initialize_plant(twin)
            before = deepcopy(mock.plant.snapshot())
            twin.apply_actions({'mv101': 1})
            twin.step()
            self.assertEqual(mock.plant.snapshot(), before)
            self.assertEqual(mock.respond(frame(30)), frame(30))
            self.assertGreater(mock.plant.state.lit101, before['LIT101'])
            self.assertEqual(mock.registers[110], round(mock.plant.snapshot()['FIT101'] * 1000))
            self.assertNotIn(120, mock.registers)
            for address in (21, 22, 23, 31):
                self.assertEqual(mock.respond(frame(address))[7:], b'\x86\x02')
            mock.respond(frame(24))
            self.assertEqual(mock.plant.state.p102, 1)
            received = list(mock.received)
            mock.apply_emergency_actions({'p101': 0, 'p102': 0, 'mv101': 0})
            self.assertEqual(mock.registers[24], 0)
            self.assertEqual(mock.registers[30], 0)
            self.assertEqual(mock.received, received)

    def test_gateway_rejects_other_stages_before_classification(self):
        pipeline = IntegrationOrchestrator(firewall_enabled=False,
            physics_params=PhysicsParams(stage1_topology='swat_stage1'))
        with ModbusGateway(('127.0.0.1', 0), ('127.0.0.1', 1), pipeline) as gateway:
            for address in (21, 22, 23, 31):
                self.assertEqual(gateway.process_request_frame(frame(address), ('127.0.0.1', 1234))[7:], b'\x86\x02')
            self.assertEqual(gateway.process_request_frame(frame(120, function=3), ('127.0.0.1', 1234))[7:], b'\x83\x02')
            self.assertEqual(pipeline.decision_history, [])

    def test_profile_rejects_invalid_area(self):
        profile = fit_profile(self.data())
        profile['physics']['tank_area_m2']['lit101'] = -1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profile.json'
            path.write_text(json.dumps(profile))
            with self.assertRaisesRegex(ValueError, 'Invalid Stage-1-only mock physics'):
                load_profile(path)


if __name__ == '__main__':
    unittest.main()
