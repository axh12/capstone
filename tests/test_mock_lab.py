import socket
import tempfile
import threading
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

from mock_scada import MockScadaServer
from modbus_gateway import ModbusGateway, receive_frame, response_frame
from orchestrator import IntegrationOrchestrator
from realtime_anomaly_detector import AnomalyDetectionResult
from run_mock_lab import LabGateway, rig_fill_thresholds
from physics_engine import PhysicsParams
from test_modbus_gateway import frame


class MockLabTests(unittest.TestCase):
    def test_arduino_distance_switch_points_convert_to_twin_depths(self):
        self.assertEqual(rig_fill_thresholds(100, 'arduino-text', None, None), (20, 80))
        self.assertEqual(rig_fill_thresholds(80, 'arduino-text', None, None), (0, 60))
        self.assertEqual(rig_fill_thresholds(None, 'arduino-text', None, None), (500, 800))
        for empty_distance, low, high in ((70, None, None),
                                          (100, 21, None), (100, None, 79)):
            with self.subTest(empty_distance=empty_distance, low=low, high=high):
                with self.assertRaises(ValueError):
                    rig_fill_thresholds(empty_distance, 'arduino-text', low, high)

    def test_unconnected_rig_transfer_simulates_before_mock_forward(self):
        pipeline = IntegrationOrchestrator(
            firewall_enabled=False,
            physics_params=PhysicsParams(stage1_topology='three_tank_transfer', dt_seconds=30),
        )
        with MockScadaServer(('127.0.0.1', 0)) as scada:
            thread = threading.Thread(target=scada.serve_forever,
                                      kwargs={'poll_interval': 0.01}, daemon=True)
            thread.start()
            try:
                with LabGateway(('127.0.0.1', 0), scada.server_address, pipeline) as gateway:
                    request = frame(address=30)
                    self.assertEqual(gateway.process_request_frame(request, ('192.0.2.1', 12345)), request)
                    state = pipeline.digital_twin.snapshot()
                    self.assertGreater(state['LIT101'], 500)
                    self.assertLess(state['LIT201'], 600)
                    self.assertEqual(state['LIT301'], 800)
                    self.assertEqual(scada.registers[30], 1)
            finally:
                scada.shutdown()
                thread.join(timeout=2)

    def test_normal_forwarded_attack_isolated_and_scada_read_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            pipeline = IntegrationOrchestrator(firewall_enabled=False,
                snort_rules_path=str(Path(directory) / "custom.rules"), snort_blocking=True)
            with MockScadaServer(("127.0.0.1", 0)) as scada:
                thread = threading.Thread(target=scada.serve_forever,
                    kwargs={"poll_interval": 0.01}, daemon=True)
                thread.start()
                try:
                    with LabGateway(("127.0.0.1", 0), scada.server_address, pipeline) as gateway:
                        normal = frame(address=30)
                        self.assertEqual(gateway.process_request_frame(normal, ("192.0.2.1", 12345)), normal)
                        attack = frame(address=20)
                        self.assertEqual(gateway.process_request_frame(attack, ("192.0.2.1", 12345)),
                                         response_frame(attack, b"\x86\x04"))
                        self.assertEqual(scada.received, [normal])
                        self.assertEqual(scada.registers[30], 1)
                        self.assertEqual(scada.registers[20], 0)
                        # Telemetry captures the command effect before the
                        # anomaly handler applies the Twin emergency response.
                        self.assertEqual(pipeline.telemetry_events[-1].process["p101"], 1)
                        read = frame(function=3, address=20)
                        with socket.create_connection(scada.server_address, timeout=2) as client:
                            client.settimeout(2)
                            client.sendall(read)
                            self.assertEqual(receive_frame(client)[7:], b"\x03\x02\x00\x00")
                        self.assertIn("06 00 14 00 01", pipeline.snort_rule_manager.rules_path.read_text())
                finally:
                    scada.shutdown()
                    thread.join(timeout=2)

    def test_mock_refuses_nonloopback_bind(self):
        with self.assertRaises(ValueError):
            MockScadaServer(("0.0.0.0", 15020))

    def test_mock_safety_hook_turns_off_previously_accepted_dosing(self):
        with tempfile.TemporaryDirectory() as directory:
            pipeline = IntegrationOrchestrator(firewall_enabled=False,
                snort_rules_path=str(Path(directory) / 'rules.txt'), snort_blocking=True)
            pipeline.anomaly_detector.feature_source = 'swat-process'
            pipeline.anomaly_detector.threshold = 0.5

            def predict(features):
                score = 0.9 if features['AIT202_pH'] < 7.15 else 0.1
                result = AnomalyDetectionResult(datetime.now(), score > 0.5,
                                                score, features, abs(score - 0.5))
                result.threshold = 0.5
                return result

            pipeline.anomaly_detector.predict = Mock(side_effect=predict)
            with MockScadaServer(('127.0.0.1', 0)) as scada:
                thread = threading.Thread(target=scada.serve_forever,
                    kwargs={'poll_interval': 0.01}, daemon=True)
                thread.start()
                try:
                    with ModbusGateway(('127.0.0.1', 0), scada.server_address,
                                       pipeline, emergency_hook=scada.apply_emergency_actions) as gateway:
                        for transaction in (1, 2):
                            request = frame(address=23, transaction=transaction)
                            self.assertEqual(gateway.process_request_frame(
                                request, ('192.0.2.1', 12345)), request)
                        self.assertEqual(scada.registers[23], 1)
                        blocked = frame(address=23, transaction=3)
                        self.assertEqual(gateway.process_request_frame(
                            blocked, ('192.0.2.1', 12345)),
                            response_frame(blocked, b'\x86\x04'))
                        self.assertEqual(scada.registers[23], 0)
                        self.assertEqual(scada.safety_events[-1][23], 0)
                        self.assertEqual(len(scada.received), 2)
                        self.assertEqual(pipeline.state_manager.snapshot()['p203'], 0)
                        self.assertEqual(pipeline.telemetry_events[-1].detection[
                            'mock_safety_actions'][23], 0)
                finally:
                    scada.shutdown()
                    thread.join(timeout=2)

    def test_recorded_features_are_native_and_labels_are_explicit(self):
        import json
        from detector_training import NATIVE_FEATURES
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'telemetry.jsonl'
            pipeline=IntegrationOrchestrator(firewall_enabled=False)
            with LabGateway(('127.0.0.1',0),('127.0.0.1',1),pipeline,
                            telemetry_file=path,label=1) as gateway:
                gateway.process_request_frame(frame(address=20),('192.0.2.1',12345))
            event=json.loads(path.read_text())
            self.assertEqual(event['label'],1)
            self.assertEqual(event['decision'],'BLOCK')
            self.assertEqual(event['model_features']['modbus_register'],20)
            self.assertEqual(event['model_features']['p101'],1)
            self.assertTrue(set(NATIVE_FEATURES)<=set(event['model_features']))
            self.assertNotIn('AIT504.Pv',event['model_features'])

    def test_new_gateway_record_matches_window_training_contract(self):
        import json
        from gateway_window_profile import features_from_event
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'session.jsonl'
            pipeline = IntegrationOrchestrator(firewall_enabled=False)
            with MockScadaServer(('127.0.0.1', 0)) as scada:
                thread = threading.Thread(target=scada.serve_forever,
                    kwargs={'poll_interval': 0.01}, daemon=True)
                thread.start()
                try:
                    with LabGateway(('127.0.0.1', 0), scada.server_address, pipeline,
                                    telemetry_file=path, label=0) as gateway:
                        for transaction in (1, 2):
                            request = frame(address=30, transaction=transaction)
                            self.assertEqual(gateway.process_request_frame(
                                request, ('192.0.2.1', 12345)), request)
                    rows = [json.loads(line) for line in path.read_text().splitlines()]
                    self.assertEqual([features_from_event(row)['packet_count'] for row in rows],
                                     [1.0, 2.0])
                finally:
                    scada.shutdown()
                    thread.join(timeout=2)

    def test_gateway_refuses_unavailable_swat_sensor_profile(self):
        from modbus_gateway import ModbusGateway
        pipeline=IntegrationOrchestrator(firewall_enabled=False)
        pipeline.anomaly_detector.calibration={'if':[0], 'lof':[0], 'z':[0]}
        pipeline.anomaly_detector.feature_source='swat'
        with self.assertRaisesRegex(ValueError,'SWaT sensors are unavailable'):
            ModbusGateway(('127.0.0.1',0),('127.0.0.1',1),pipeline)
