"""Real loopback TCP tests with an isolated mock SCADA destination."""
import socket
import socketserver
import struct
import tempfile
import threading
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

from modbus_gateway import ModbusGateway, receive_frame, response_frame
from network_integration import PacketEvent
from orchestrator import IntegrationOrchestrator
from realtime_anomaly_detector import AnomalyDetectionResult
from gateway_window_profile import GATEWAY_WINDOW_FEATURES


def frame(function=6, address=20, value=1, transaction=1):
    return struct.pack(">HHHBBHH", transaction, 0, 6, 1, function, address, value)


class MockScadaHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(1)
        request = receive_frame(self.request)
        self.server.received.append(request)
        self.request.sendall(request)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.scada = socketserver.ThreadingTCPServer(("127.0.0.1", 0), MockScadaHandler)
        self.scada.received = []
        self.pipeline = IntegrationOrchestrator(firewall_enabled=False,
            snort_rules_path=str(Path(self.directory.name) / "custom.rules"), snort_blocking=True)
        self.anomaly = False
        def predict(features):
            return AnomalyDetectionResult(datetime.now(), self.anomaly,
                0.9 if self.anomaly else 0.01, features, 0.5)
        self.pipeline.anomaly_detector.predict = Mock(side_effect=predict)
        self.gateway = ModbusGateway(("127.0.0.1", 0), self.scada.server_address, self.pipeline, timeout=0.5)
        self.threads = []
        for server in (self.scada, self.gateway):
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            thread.start()
            self.threads.append(thread)
        self.addCleanup(self.cleanup_servers)

    def cleanup_servers(self):
        for server in (self.gateway, self.scada):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=1)
        self.directory.cleanup()

    def exchange(self, request):
        with socket.create_connection(self.gateway.server_address, timeout=2) as client:
            client.settimeout(2)
            client.sendall(request)
            return receive_frame(client)

    def test_normal_write_reaches_scada_and_updates_twin(self):
        request = frame()
        self.assertEqual(self.exchange(request), request)
        self.assertEqual(self.scada.received, [request])
        self.assertEqual(self.pipeline.state_manager.snapshot()["p101"], 1)
        self.assertEqual(self.pipeline.decision_history[-1]["decision"], "ALLOW")
        self.assertFalse(self.pipeline.snort_rule_manager.rules_path.exists())

    def test_read_only_physical_sample_reaches_twin_before_scoring(self):
        connector = Mock()
        connector.read_state.return_value = {'LIT101': 700.0, 'FIT101': 4.2}
        self.pipeline.stage1_connector = connector
        request = frame(function=3, address=1, value=1)
        self.exchange(request)
        connector.read_state.assert_called_once_with()
        self.assertEqual(self.pipeline.digital_twin.snapshot()['LIT101'], 700.0)
        self.assertEqual(self.pipeline.state_manager.snapshot()['FIT101'], 4.2)
        self.assertEqual(self.pipeline.telemetry_events[-1].process['LIT101'], 700.0)

    def test_physical_sample_failure_returns_device_error_without_forwarding(self):
        connector = Mock()
        connector.read_state.side_effect = TimeoutError('serial telemetry stopped')
        self.pipeline.stage1_connector = connector
        request = frame()
        self.assertEqual(self.exchange(request), response_frame(request, b'\x86\x04'))
        self.assertEqual(self.scada.received, [])

    def test_triggering_and_repeated_anomalous_commands_never_reach_scada(self):
        self.anomaly = True
        for transaction in (1, 2):
            request = frame(transaction=transaction)
            self.assertEqual(self.exchange(request),
                             response_frame(request, b"\x86\x04"))
        self.assertEqual(self.scada.received, [])
        self.assertEqual(self.pipeline.decision_history[-1]["decision"], "BLOCK")
        rules = self.pipeline.snort_rule_manager.rules_path.read_text()
        self.assertIn("drop tcp", rules)
        self.assertIn("06 00 14 00 01", rules)
        self.assertEqual(self.pipeline.telemetry_events[0].network["function_code"], 6)

    def test_custom_physical_forwarder_receives_only_allowed_requests(self):
        forwarder = Mock(side_effect=lambda request: request)
        self.gateway.forwarder = forwarder
        allowed = frame(address=30)
        self.assertEqual(self.exchange(allowed), allowed)
        self.anomaly = True
        blocked = frame(address=20, transaction=2)
        self.assertEqual(self.exchange(blocked), response_frame(blocked, b'\x86\x04'))
        forwarder.assert_called_once_with(allowed)
        self.assertEqual(self.scada.received, [])

    def test_detection_failure_never_reaches_scada(self):
        self.pipeline.anomaly_detector.predict.side_effect = RuntimeError("detector unavailable")
        self.assertEqual(self.exchange(frame())[7:], b"\x86\x04")
        self.assertEqual(self.scada.received, [])

    def test_sem_failure_never_reaches_scada(self):
        self.pipeline._extract_candidate_signature = Mock(side_effect=RuntimeError("SEM unavailable"))
        self.assertEqual(self.exchange(frame())[7:], b"\x86\x04")
        self.assertEqual(self.scada.received, [])

    def test_unavailable_scada_returns_failure_without_retry(self):
        self.scada.shutdown()
        self.scada.server_close()
        self.assertEqual(self.exchange(frame())[7:], b"\x86\x04")
        self.assertEqual(self.scada.received, [])

    def test_unrelated_normal_command_passes_after_anomaly(self):
        self.anomaly = True
        self.exchange(frame())
        self.anomaly = False
        request = frame(address=30, transaction=2)
        self.assertEqual(self.exchange(request), request)
        self.assertEqual(self.scada.received, [request])

    def test_rolling_batch_uses_only_one_source_and_current_request(self):
        first = frame(address=20)
        other = frame(address=30, transaction=2)
        current = frame(address=23, transaction=3)
        self.assertEqual(self.gateway.process_request_frame(first, ('192.0.2.1', 1001)), first)
        self.assertEqual(self.gateway.process_request_frame(other, ('192.0.2.2', 1002)), other)
        self.anomaly = True
        self.assertEqual(self.gateway.process_request_frame(current, ('192.0.2.1', 1003)),
                         response_frame(current, b'\x86\x04'))
        event = self.pipeline.telemetry_events[-1]
        self.assertEqual(event.network['src_ip'], '192.0.2.1')
        self.assertEqual(event.network['src_port'], 1003)
        self.assertEqual(event.network_statistics['packet_count'], 2)
        self.assertEqual(event.network_statistics['unique_src_ips'], 1)
        self.assertEqual(event.detection['window_seconds'], 60)
        self.assertEqual(event.detection['window_packet_count'], 2)
        self.assertEqual(event.detection['window_command_counts'], [
            {'function_code': 6, 'register': 20, 'value': 1, 'count': 1},
            {'function_code': 6, 'register': 23, 'value': 1, 'count': 1},
        ])
        self.assertEqual(self.pipeline.stats['packets_processed'], 3)
        self.assertEqual(self.scada.received, [first, other])
        rules = self.pipeline.snort_rule_manager.rules_path.read_text()
        self.assertIn('register 23 value 1', rules)
        self.assertNotIn('register 20 value 1', rules)

    def test_rolling_window_expires_old_packets(self):
        start = datetime(2026, 1, 1)
        def packet(ip, seconds):
            return PacketEvent(ip, '192.0.2.10', 1000, 5020,
                               'tcp', 12, start + timedelta(seconds=seconds))
        self.assertEqual(len(self.gateway.packets_for_source(packet('192.0.2.1', 0))), 1)
        self.assertEqual(len(self.gateway.packets_for_source(packet('192.0.2.2', 10))), 1)
        self.assertEqual(len(self.gateway.packets_for_source(packet('192.0.2.1', 61))), 1)
        self.assertEqual(len(self.gateway._source_packets['192.0.2.2']), 1)

    def test_state_only_counterfactual_blocks_dosing_but_allows_later_valve(self):
        self.pipeline.anomaly_detector.feature_source = 'swat-process'
        self.pipeline.anomaly_detector.threshold = 0.5

        def predict(features):
            score = 0.9 if features['AIT202_pH'] < 7.2 else 0.1
            result = AnomalyDetectionResult(datetime.now(), score > 0.5,
                                            score, features, abs(score - 0.5))
            result.threshold = 0.5
            return result

        self.pipeline.anomaly_detector.predict.side_effect = predict
        dosing = frame(address=23)
        self.assertEqual(self.exchange(dosing), response_frame(dosing, b"\x86\x04"))
        self.assertEqual(self.pipeline.decision_history[-1]['decision'], 'BLOCK')
        self.assertEqual(self.pipeline.telemetry_events[-1].detection['twin_commit'], 'withheld')
        self.assertEqual(self.pipeline.state_manager.snapshot()['p203'], 0)
        repeated = frame(address=23, transaction=2)
        self.assertEqual(self.exchange(repeated), response_frame(repeated, b"\x86\x04"))
        self.assertEqual(self.pipeline.decision_history[-1]['decision'], 'BLOCK')
        valve = frame(address=30, transaction=3)
        self.assertEqual(self.exchange(valve), valve)
        self.assertEqual(self.pipeline.decision_history[-1]['decision'], 'ALLOW')
        self.assertEqual(self.scada.received, [valve])
        rules = self.pipeline.snort_rule_manager.rules_path.read_text()
        self.assertIn('register 23 value 1', rules)
        self.assertNotIn('register 30 value 1', rules)

    def test_window_profile_scores_alternative_with_same_network_window(self):
        self.pipeline.anomaly_detector.feature_source = 'gateway-window'
        self.pipeline.anomaly_detector.threshold = 0.5
        observed = []

        def predict(features):
            observed.append((features['packet_count'], features['bytes_per_sec'],
                             features['AIT202_pH']))
            result = AnomalyDetectionResult(datetime.now(), False, 0.1,
                                            features, 0.4)
            result.threshold = 0.5
            return result

        self.pipeline.anomaly_detector.predict.side_effect = predict
        request = frame(address=30)
        self.assertEqual(self.exchange(request), request)
        self.assertEqual(len(observed), 2)
        self.assertEqual([row[:2] for row in observed], [(1.0, 0.2), (1.0, 0.2)])

    def test_window_profile_rejects_mismatched_duration_before_binding(self):
        self.pipeline.anomaly_detector.calibration = {}
        self.pipeline.anomaly_detector.feature_source = 'gateway-window'
        self.pipeline.anomaly_detector.FEATURE_ORDER = GATEWAY_WINDOW_FEATURES
        self.pipeline.anomaly_detector.metadata = {
            'window_seconds': 60.0, 'window_scope': 'per_source_modbus_request'}
        with self.assertRaisesRegex(ValueError, 'same 60-second'):
            ModbusGateway(('127.0.0.1', 0), self.scada.server_address,
                          self.pipeline, window_seconds=30)

    def test_window_only_alarm_does_not_create_overbroad_command_rule(self):
        self.pipeline.anomaly_detector.feature_source = 'gateway-window'
        self.pipeline.anomaly_detector.threshold = 0.5

        def predict(features):
            high = features['packet_count'] >= 2
            result = AnomalyDetectionResult(datetime.now(), high,
                                            0.9 if high else 0.1, features, 0.4)
            result.threshold = 0.5
            return result

        self.pipeline.anomaly_detector.predict.side_effect = predict
        first = frame(address=30)
        second = frame(address=23, transaction=2)
        self.assertEqual(self.exchange(first), first)
        self.assertEqual(self.exchange(second), second)
        self.assertEqual(self.pipeline.decision_history[-1]['decision'], 'ALLOW')
        self.assertTrue(self.pipeline.telemetry_events[-1].detection['is_anomaly'])
        self.assertFalse(self.pipeline.snort_rule_manager.rules_path.exists())

    def test_truncated_frame_closes_without_forwarding(self):
        with socket.create_connection(self.gateway.server_address, timeout=2) as client:
            client.settimeout(2)
            client.sendall(frame()[:9])
            client.shutdown(socket.SHUT_WR)
            self.assertEqual(client.recv(1), b"")
        self.assertEqual(self.scada.received, [])

    def test_invalid_actuator_value_never_reaches_scada(self):
        self.assertEqual(self.exchange(frame(value=2))[7:], b"\x86\x03")
        self.assertEqual(self.scada.received, [])
        self.assertEqual(self.pipeline.state_manager.snapshot()["p101"], 0)

    def test_unknown_register_never_reaches_scada(self):
        self.assertEqual(self.exchange(frame(address=99))[7:], b"\x86\x02")
        self.assertEqual(self.scada.received, [])

    def test_blocked_read_returns_twin_sensor(self):
        self.anomaly = True
        reply = self.exchange(frame(function=3, address=1, value=1))
        self.assertEqual(reply[7:], b"\x03\x02\x01\xf4")
        self.assertEqual(self.scada.received, [])

    def test_fragmented_frame_and_multiple_requests_on_connection(self):
        with socket.create_connection(self.gateway.server_address, timeout=2) as client:
            client.settimeout(2)
            request = frame()
            client.sendall(request[:5])
            client.sendall(request[5:])
            self.assertEqual(receive_frame(client), request)
            second = frame(value=0, transaction=2)
            client.sendall(second)
            self.assertEqual(receive_frame(client), second)
        self.assertEqual(self.scada.received, [request, second])

    def test_bad_protocol_header_closes_without_forwarding(self):
        request = bytearray(frame())
        request[3] = 1
        with socket.create_connection(self.gateway.server_address, timeout=2) as client:
            client.settimeout(2)
            client.sendall(request)
            try:
                self.assertEqual(client.recv(1), b"")
            except ConnectionResetError:
                pass
        self.assertEqual(self.scada.received, [])


if __name__ == "__main__":
    unittest.main()
