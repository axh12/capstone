"""Offline component and pipeline tests; no capture or firewall deployment."""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, patch

import numpy as np

from physical_stage1 import ArduinoNanoSerialStage1Connector, ModbusReadOnlyStage1Connector
from feature_extractor import FeatureExtractor
from network_integration import PacketEvent
from orchestrator import IntegrationOrchestrator
from physics_engine import PhysicsParams
from realtime_anomaly_detector import RealTimeAnomalyDetector, AnomalyDetectionResult
from rule_generator import RuleGenerator
from snort_integration import SnortRuleManager
from state_manager import StateManager, StateValidator
from telemetry import TelemetryEvent, build_state_change


def signature(register=20):
    return {"modbus_commands": [{"function": 6, "register": register, "value": 1}]}


class StateTests(unittest.TestCase):
    def test_valid_transition_records_version_previous_and_delta(self):
        manager = StateManager({"LIT101": 500})
        transition = manager.apply_patch({"LIT101": 510})
        self.assertEqual(manager.version, 1)
        self.assertEqual(transition.previous, {"LIT101": 500})
        self.assertEqual(transition.changes["LIT101"]["delta"], 10)

    def test_rejection_preserves_state_and_version(self):
        manager = StateManager({"LIT101": 500})
        with self.assertRaises(ValueError):
            manager.apply_patch({"LIT101": -1})
        self.assertEqual(manager.snapshot(), {"LIT101": 500})
        self.assertEqual(manager.version, 0)

    def test_snapshot_is_independent(self):
        manager = StateManager({"nested": {"value": 1}})
        snapshot = manager.snapshot()
        snapshot["nested"]["value"] = 2
        self.assertEqual(manager.snapshot()["nested"]["value"], 1)

    def test_nonfinite_sensor_values_rejected(self):
        for value in (float("nan"), float("inf"), -float("inf")):
            with self.subTest(value=value):
                self.assertFalse(StateValidator().validate({"LIT101": value})[0])

    def test_fractional_actuator_rejected(self):
        self.assertFalse(StateValidator().validate({"p101": 0.5})[0])

    def test_invalid_actuator_type_returns_rejection(self):
        for value in (None, "bad", []):
            with self.subTest(value=value):
                self.assertFalse(StateValidator().validate({"p101": value})[0])


class FeatureTests(unittest.TestCase):
    def test_empty_window(self):
        self.assertTrue(all(value == 0 for value in FeatureExtractor().extract_network_features().values()))

    def test_known_packet_statistics(self):
        extractor = FeatureExtractor(window_seconds=2)
        for size, source in ((40, "a"), (100, "b")):
            extractor.add_packet({"size": size, "src_ip": source, "dst_ip": "c"})
        actual = extractor.extract_network_features()
        expected = {"total_bytes": 140, "packet_count": 2, "bytes_per_sec": 70,
                    "packets_per_sec": 1, "avg_packet_size": 70, "bytes_per_packet": 70,
                    "max_packet_size": 100, "packet_size_range": 60,
                    "small_packets_count": 1, "unique_src_ips": 2,
                    "unique_dst_ips": 1, "unique_ip_pairs": 2}
        self.assertEqual(actual, expected)

    def test_reset_removes_previous_packets(self):
        extractor = FeatureExtractor()
        extractor.add_packet({"size": 100})
        extractor.reset_window()
        self.assertEqual(extractor.extract_network_features()["packet_count"], 0)

    def test_model_feature_schema_and_order(self):
        detector = RealTimeAnomalyDetector()
        vector = FeatureExtractor().build_feature_vector({"P1_STATE": 3})
        self.assertEqual(set(vector), set(detector.FEATURE_ORDER))
        values = {name: i for i, name in enumerate(detector.FEATURE_ORDER)}
        np.testing.assert_array_equal(detector.prepare_features(values), np.arange(20).reshape(1, 20))


class DetectorTests(unittest.TestCase):
    def test_unloaded_model_rejected(self):
        with self.assertRaises(RuntimeError):
            RealTimeAnomalyDetector().predict({})

    def test_missing_artifact_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                RealTimeAnomalyDetector(str(Path(directory) / "missing.pkl"))

    def test_threshold_boundary_with_controlled_models(self):
        detector = RealTimeAnomalyDetector()
        detector.scaler = Mock()
        detector.scaler.transform.return_value = np.zeros((1, 20))
        detector.isolation_forest = Mock()
        detector.isolation_forest.decision_function.return_value = np.array([0.])
        detector.lof = Mock()
        detector.lof.decision_function.return_value = np.array([0.])
        detector.normal_mean = np.zeros(20)
        detector.normal_std = np.ones(20)
        score = detector.predict({}).ensemble_score
        detector.threshold = score
        self.assertFalse(detector.predict({}).is_anomaly)
        detector.threshold = score - 0.001
        self.assertTrue(detector.predict({}).is_anomaly)


class TelemetryTests(unittest.TestCase):
    def test_deltas_and_json_round_trip(self):
        previous, current = {"level": 10, "mode": "off"}, {"level": 15, "mode": "on"}
        changes = build_state_change(previous, current)
        self.assertEqual(changes["level"], {"from": 10, "to": 15, "delta": 5})
        self.assertEqual(changes["mode"], {"from": "off", "to": "on"})
        event = TelemetryEvent.create("event-1", process=current, previous_process=previous, state_change=changes)
        self.assertEqual(json.loads(event.to_json()), event.to_dict())
        self.assertIsNotNone(datetime.fromisoformat(event.timestamp).tzinfo)
        self.assertEqual(previous["level"], 10)


class Stage1ConnectorTests(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.client.connect.return_value = True
        self.client.read_holding_registers.return_value.isError.return_value = False
        self.client.read_holding_registers.return_value.registers = [500]
        package = ModuleType("pymodbus")
        module = ModuleType("pymodbus.client")
        module.ModbusTcpClient = Mock(return_value=self.client)
        self.modules = patch.dict(sys.modules, {"pymodbus": package, "pymodbus.client": module})
        self.modules.start()
        self.addCleanup(self.modules.stop)
        self.connector = ModbusReadOnlyStage1Connector("192.0.2.10", register_map={"LIT101": 10})

    def test_reads_register_and_closes_without_writes(self):
        self.assertEqual(self.connector.read_state(), {"LIT101": 500})
        self.client.read_holding_registers.assert_called_once_with(10, count=1, unit=1)
        self.client.close.assert_called_once_with()
        self.assertFalse(any(call[0].startswith("write") for call in self.client.mock_calls))

    def test_connection_failure_closes_client(self):
        self.client.connect.return_value = False
        with self.assertRaises(ConnectionError):
            self.connector.read_state()
        self.client.close.assert_called_once_with()
        self.client.read_holding_registers.assert_not_called()

    def test_register_error_closes_client(self):
        self.client.read_holding_registers.return_value.isError.return_value = True
        with self.assertRaises(RuntimeError):
            self.connector.read_state()
        self.client.close.assert_called_once_with()

    def test_nano_serial_json_converts_distance_and_outlet_flow(self):
        connector = ArduinoNanoSerialStage1Connector('/dev/example', empty_distance_mm=400)
        serial_port = Mock()
        serial_port.readline.return_value = (
            b'{"distance_mm":125,"outlet_flow_lpm":10,"inlet_pump_on":1,"outlet_pump_on":0}\n'
        )
        serial_port.in_waiting = 0
        connector._serial = serial_port
        self.assertEqual(connector.read_state(), {
            'LIT101': 275.0, 'FIT201': 0.6, 'mv101': 1, 'p101': 0,
        })
        connector.close()
        serial_port.close.assert_called_once_with()
        serial_port.write.assert_not_called()

    def test_nano_serial_accepts_displayed_water_level_directly(self):
        connector = ArduinoNanoSerialStage1Connector('/dev/example')
        self.assertEqual(connector._decode(
            b'{"water_level_mm":275,"outlet_flow_lpm":10}\n'),
            {'LIT101': 275.0, 'FIT201': 0.6})

    def test_nano_original_sketch_pairs_distance_and_flow_at_9600_baud(self):
        connector = ArduinoNanoSerialStage1Connector(
            '/dev/example', empty_distance_mm=100, baudrate=9600,
            serial_format='arduino-text')
        serial_port = Mock()
        serial_port.readline.side_effect = [b'Distance: 8 cm\r\n', b'Flow: 7.50 L/min\r\n']
        serial_port.in_waiting = 0
        connector._serial = serial_port
        state = connector.read_state()
        self.assertEqual(state['LIT101'], 20.0)
        self.assertAlmostEqual(state['FIT201'], 0.45)
        serial_port.write.assert_not_called()

    def test_nano_original_sketch_preserves_raw_distance_without_empty_reference(self):
        connector = ArduinoNanoSerialStage1Connector(
            '/dev/example', baudrate=9600, serial_format='arduino-text')
        state = connector._decode_arduino_pair(
            b'Distance: 12 cm\n', b'Flow: 7.50 L/min\n')
        self.assertEqual(state['distance_cm'], 12.0)
        self.assertAlmostEqual(state['FIT201'], 0.45)
        self.assertNotIn('LIT101', state)

    def test_nano_original_sketch_rejects_no_echo_and_incomplete_pair(self):
        connector = ArduinoNanoSerialStage1Connector(
            '/dev/example', empty_distance_mm=100, serial_format='arduino-text')
        with self.assertRaisesRegex(ValueError, 'no-echo'):
            connector._decode_arduino_pair(b'Distance: 99 cm\n', b'Flow: 0.00 L/min\n')
        with self.assertRaisesRegex(ValueError, 'consecutive'):
            connector._decode_arduino_pair(b'Distance: 8 cm\n', b'Flow: bad L/min\n')
        serial_port = Mock()
        serial_port.readline.side_effect = [b'Distance: 8 cm\n', b'']
        connector._serial = serial_port
        with self.assertRaises(TimeoutError):
            connector.read_state()
        self.assertEqual(connector._decode(
            b'{"water_level_mm":275,"outlet_flow_m3h":0.6}\n'),
            {'LIT101': 275.0, 'FIT201': 0.6})

    def test_nano_serial_rejects_invalid_or_missing_measurements(self):
        connector = ArduinoNanoSerialStage1Connector('/dev/example', empty_distance_mm=400)
        for line in (b'{"distance_mm":401,"outlet_flow_lpm":10}\n',
                     b'{"distance_mm":10,"outlet_flow_lpm":-1}\n',
                     b'{"distance_mm":10}\n',
                     b'{"distance_mm":10,"water_level_mm":390,"outlet_flow_lpm":1}\n',
                     b'{"water_level_mm":10,"outlet_flow_lpm":1,"outlet_flow_m3h":0.06}\n',
                     b'{"distance_mm":10,"outlet_flow_lpm":1,"inlet_pump_on":2}\n'):
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    connector._decode(line)


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.manager = SnortRuleManager(str(Path(self.directory.name) / "custom.rules"), blocking=True)

    def test_sensor_only_and_invalid_commands_produce_no_rule(self):
        for value in ({"affected_sensors": ["LIT101"]},
                      {"modbus_commands": [{"function": 6, "register": -1, "value": 1}]},
                      {"modbus_commands": [{"function": 3, "register": 20, "value": 1}]}):
            self.assertEqual(self.manager.rules_from_signature(value), [])

    def test_duplicate_rule_persisted_once(self):
        rule = self.manager.rules_from_signature(signature())[0]
        self.manager.rules_from_signature(signature())
        self.assertEqual(self.manager.write().read_text().count(rule), 1)
        self.assertTrue(rule.startswith("drop tcp"))

    def test_expired_rules_removed(self):
        rule = self.manager.rules_from_signature(signature())[0]
        self.manager._rule_expiry[rule] = datetime.now(timezone.utc) - timedelta(seconds=1)
        self.assertEqual(self.manager.cleanup_expired(), 1)
        self.assertNotIn(rule, self.manager.write().read_text())

    def test_discard_candidate_removes_pending_rule(self):
        generator = RuleGenerator(self.manager)
        candidate = generator.generate(signature())[0]
        generator.discard()
        self.assertNotIn(candidate.rule, self.manager.write().read_text())

    def test_activation_does_not_publish_unapproved_candidate(self):
        generator = RuleGenerator(self.manager)
        candidates = generator.generate({"modbus_commands": signature(20)["modbus_commands"] + signature(21)["modbus_commands"]})
        generator.activate(candidates[0])
        content = self.manager.rules_path.read_text()
        self.assertIn(candidates[0].rule, content)
        self.assertNotIn(candidates[1].rule, content)

    def test_discard_duplicate_preserves_previously_active_rule(self):
        generator = RuleGenerator(self.manager)
        candidate = generator.generate(signature())[0]
        generator.activate(candidate)
        generator.generate(signature())
        generator.discard()
        self.assertIn(candidate.rule, self.manager.write().read_text())


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.pipeline = IntegrationOrchestrator(firewall_enabled=False, enable_digital_twin=False)
        self.packet = PacketEvent("192.0.2.1", "192.0.2.2", 12345, 5020, "tcp", 60, datetime.now())

    def detection(self, anomaly):
        return AnomalyDetectionResult(datetime.now(), anomaly, 0.9 if anomaly else 0.01, {}, 0.5)

    def test_normal_batch_never_calls_enforcement(self):
        with patch.object(self.pipeline.anomaly_detector, "predict", return_value=self.detection(False)), \
             patch.object(self.pipeline, "_extract_candidate_signature", return_value=signature()), \
             patch.object(self.pipeline, "_handle_anomaly") as enforce:
            result = self.pipeline._process_packet_batch([self.packet])
        self.assertEqual(result["decision"], "ALLOW")
        enforce.assert_not_called()
        self.assertEqual(self.pipeline.feature_extractor.packet_buffer, [])

    def test_anomalous_batch_calls_enforcement_with_signature(self):
        with patch.object(self.pipeline.anomaly_detector, "predict", return_value=self.detection(True)), \
             patch.object(self.pipeline, "_extract_candidate_signature", return_value=signature()), \
             patch.object(self.pipeline, "_handle_anomaly") as enforce:
            result = self.pipeline._process_packet_batch([self.packet])
        self.assertEqual(result["decision"], "BLOCK")
        enforce.assert_called_once()
        self.assertEqual(enforce.call_args.args[2]["modbus_commands"], signature()["modbus_commands"])
        self.assertEqual(self.pipeline.telemetry_events[0].network["register"], 20)

    def test_detection_failure_does_not_enforce(self):
        with patch.object(self.pipeline.anomaly_detector, "predict", side_effect=RuntimeError("inference failed")), \
             patch.object(self.pipeline, "_extract_candidate_signature", return_value=signature()), \
             patch.object(self.pipeline, "_handle_anomaly") as enforce:
            with self.assertRaises(RuntimeError):
                self.pipeline._process_packet_batch([self.packet])
        enforce.assert_not_called()
        self.assertEqual(self.pipeline.decision_history, [])

    def test_empty_command_list_is_valid_normal_traffic(self):
        with patch.object(self.pipeline.anomaly_detector, "predict", return_value=self.detection(False)), \
             patch.object(self.pipeline, "_extract_candidate_signature", return_value={"modbus_commands": []}):
            self.assertEqual(self.pipeline._process_packet_batch([self.packet])["decision"], "ALLOW")

    def test_stage1_sync_rejects_invalid_read(self):
        self.pipeline.stage1_connector = Mock()
        self.pipeline.stage1_connector.read_state.return_value = {"LIT101": 5000}
        with self.assertRaises(ValueError):
            self.pipeline.sync_stage1()
        self.assertEqual(self.pipeline.state_manager.snapshot(), {})

    def test_stage1_sync_valid_read(self):
        self.pipeline.stage1_connector = Mock()
        self.pipeline.stage1_connector.read_state.return_value = {"LIT101": 500}
        self.pipeline.sync_stage1()
        self.assertEqual(self.pipeline.state_manager.snapshot()["LIT101"], 500)
        self.pipeline.stage1_connector.read_state.assert_called_once_with()

    def test_stage1_sync_updates_twin_and_rejects_unknown_fields(self):
        pipeline = IntegrationOrchestrator(firewall_enabled=False)
        pipeline.stage1_connector = Mock()
        pipeline.stage1_connector.read_state.return_value = {'LIT101': 650.0}
        pipeline.sync_stage1()
        self.assertEqual(pipeline.digital_twin.snapshot()['LIT101'], 650.0)
        self.assertEqual(pipeline.state_manager.snapshot()['LIT101'], 650.0)
        pipeline.stage1_connector.read_state.return_value = {'distance_mm': 42.0}
        with self.assertRaisesRegex(ValueError, 'Unknown physical Stage 1 field'):
            pipeline.sync_stage1()
        self.assertEqual(pipeline.digital_twin.snapshot()['LIT101'], 650.0)

    def test_stage1_raw_distance_reaches_rig_twin_without_depth_reference(self):
        pipeline = IntegrationOrchestrator(
            firewall_enabled=False,
            physics_params=PhysicsParams(stage1_topology='three_tank_transfer'))
        pipeline.stage1_connector = Mock()
        pipeline.stage1_connector.read_state.return_value = {
            'distance_cm': 9.0, 'FIT201': 0.45}
        self.assertEqual(pipeline.sync_stage1(), {'distance_cm': 9.0, 'FIT201': 0.45})
        self.assertEqual(pipeline.state_manager.snapshot()['distance_cm'], 9.0)
        self.assertEqual(pipeline.digital_twin.snapshot()['FIT201'], 0.45)
        self.assertEqual(pipeline.digital_twin.step()['mv101'], 1)


if __name__ == "__main__":
    unittest.main()


class ProcessNoveltyAttributionTests(unittest.TestCase):
    def test_unrelated_write_is_not_promoted_to_attack_rule(self):
        from orchestrator import IntegrationOrchestrator
        candidate = {'attack_type': 'PROCESS_NOVELTY',
            'feature_deviations': {'p201': {'value': 1}},
            'modbus_commands': [{'function': 6, 'register': 30, 'value': 1}]}
        IntegrationOrchestrator._attribute_process_novelty(candidate)
        self.assertEqual(candidate['modbus_commands'], [])

    def test_matching_unseen_actuator_write_keeps_command_signature(self):
        from orchestrator import IntegrationOrchestrator
        command = {'function': 6, 'register': 21, 'value': 1}
        candidate = {'attack_type': 'PROCESS_NOVELTY',
            'feature_deviations': {'p201': {'value': 1}}, 'modbus_commands': [command]}
        IntegrationOrchestrator._attribute_process_novelty(candidate)
        self.assertEqual(candidate['modbus_commands'], [command])


class EmergencyPumpResetTests(unittest.TestCase):
    def test_process_novelty_response_stops_dosing_pump(self):
        from orchestrator import IntegrationOrchestrator
        from realtime_anomaly_detector import AnomalyDetectionResult
        from datetime import datetime
        pipeline = IntegrationOrchestrator(firewall_enabled=False)
        pipeline.digital_twin.apply_actions({'p203': 1})
        detection = AnomalyDetectionResult(datetime.now(), True, 1.0, {}, 0.1, 'PROCESS_NOVELTY')
        pipeline._trigger_digital_twin_response(detection)
        self.assertEqual(pipeline.state_manager.snapshot()['p203'], 0)
        self.assertEqual(pipeline.digital_twin.snapshot()['p203'], 0)
