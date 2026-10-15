"""Inline Modbus/TCP gateway with classification before SCADA forwarding.

Supports FC03 holding-register reads and FC06 binary actuator writes.
Blocked traffic receives the isolated Twin response. Internal failures return
a Modbus server-device-failure exception and never bypass classification.
"""
from __future__ import annotations

import argparse
import logging
import socket
import socketserver
import struct
import threading
import json
import math
from collections import deque
from pathlib import Path
from copy import deepcopy
from datetime import datetime, timedelta

from network_integration import PacketEvent
from orchestrator import IntegrationOrchestrator
from physical_stage1 import NullStage1Connector

ACTUATORS = {20: "p101", 21: "p201", 22: "p301", 30: "mv101", 31: "mv201", 23: "p203"}
SENSORS = {1: "LIT101", 2: "LIT201", 3: "LIT301", 10: "FIT101", 11: "FIT201", 12: "FIT301"}


def receive_exact(connection, count):
    data = bytearray()
    while len(data) < count:
        chunk = connection.recv(count - len(data))
        if not chunk:
            raise EOFError("Truncated Modbus frame")
        data.extend(chunk)
    return bytes(data)


def receive_frame(connection):
    header = receive_exact(connection, 7)
    _, protocol, length, _ = struct.unpack(">HHHB", header)
    if protocol != 0 or not 2 <= length <= 254:
        raise ValueError("Invalid MBAP header")
    return header + receive_exact(connection, length - 1)


def response_frame(request, pdu):
    return request[:4] + struct.pack(">H", len(pdu) + 1) + request[6:7] + pdu


class ModbusGateway(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, upstream, pipeline, timeout=3,
                 telemetry_file=None, label=None, emergency_hook=None,
                 window_seconds=60, forwarder=None):
        if pipeline.digital_twin is None:
            raise ValueError("Gateway requires the Physics Engine")
        if not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("Window duration must be finite and positive")
        self.upstream = upstream
        self.forwarder = forwarder
        self.pipeline = pipeline
        self.timeout = timeout
        self.telemetry_file = Path(telemetry_file) if telemetry_file else None
        self.label = label
        self.emergency_hook = emergency_hook
        self.window_seconds = window_seconds
        self._source_packets = {}
        self.pipeline.feature_extractor.window_seconds = window_seconds
        self._blocked_commands = set()
        if label not in (None, 0, 1):
            raise ValueError("Observation label must be 0, 1 or absent")
        topology = pipeline.digital_twin.params.stage1_topology
        if (topology != 'swat' and pipeline.anomaly_detector.calibration is not None
                and pipeline.anomaly_detector.metadata.get('plant_topology') != topology):
            raise ValueError('Detector was not calibrated for the selected plant topology')
        if pipeline.anomaly_detector.calibration is not None:
            from detector_training import NATIVE_FEATURES
            from research_state_profile import RESEARCH_STATE_FEATURES, RESEARCH_PROCESS_FEATURES
            from gateway_window_profile import GATEWAY_WINDOW_FEATURES, WINDOW_SECONDS
            supported = {
                'native-twin': NATIVE_FEATURES,
                'swat-stage1': RESEARCH_STATE_FEATURES,
                'swat-process': RESEARCH_PROCESS_FEATURES,
                'gateway-window': GATEWAY_WINDOW_FEATURES,
            }
            if pipeline.anomaly_detector.FEATURE_ORDER != supported.get(pipeline.anomaly_detector.feature_source):
                raise ValueError("Gateway requires a matching runtime feature schema; SWaT sensors are unavailable when the Twin does not produce them")
            if pipeline.anomaly_detector.feature_source == 'gateway-window':
                metadata = pipeline.anomaly_detector.metadata
                if (window_seconds != WINDOW_SECONDS or metadata.get('window_seconds') != WINDOW_SECONDS
                        or metadata.get('window_scope') != 'per_source_modbus_request'):
                    raise ValueError('gateway-window model and gateway must use the same 60-second per-source request window')
            if pipeline.anomaly_detector.feature_source in ('swat-stage1', 'swat-process', 'gateway-window'):
                from research_state_profile import initialize_twin_from_training_reference
                initialize_twin_from_training_reference(
                    pipeline.digital_twin,
                    pipeline.anomaly_detector.metadata.get('normal_reference', {}),
                )
                pipeline.state_manager.transition(pipeline.digital_twin.snapshot())
        self.transaction_lock = threading.RLock()
        super().__init__(address, GatewayHandler)

    def packets_for_source(self, packet):
        """Include this request in its source's trailing time window."""
        cutoff = packet.timestamp - timedelta(seconds=self.window_seconds)
        for source_ip, packets in list(self._source_packets.items()):
            while packets and packets[0].timestamp < cutoff:
                packets.popleft()
            if not packets:
                del self._source_packets[source_ip]
        packets = self._source_packets.setdefault(packet.src_ip, deque())
        packets.append(packet)
        return list(packets)

    def forward_allowed_request(self, request):
        """Send only an allowed request to the configured downstream device."""
        if self.forwarder is not None:
            return self.forwarder(request)
        with socket.create_connection(self.upstream, timeout=self.timeout) as upstream:
            upstream.settimeout(self.timeout)
            upstream.sendall(request)
            return receive_frame(upstream)

    def twin_response(self, request):
        function = request[7]
        if function not in (3, 6):
            return response_frame(request, bytes([function | 0x80, 1])), False
        if len(request) != 12:
            return response_frame(request, bytes([function | 0x80, 3])), False
        address, value = struct.unpack(">HH", request[8:12])
        twin = self.pipeline.digital_twin
        if function == 6:
            if address not in ACTUATORS:
                return response_frame(request, b"\x86\x02"), False
            if value not in (0, 1):
                return response_frame(request, b"\x86\x03"), False
            previous = deepcopy(twin.state)
            try:
                twin.apply_actions({ACTUATORS[address]: value})
                self.pipeline.state_manager.transition(twin.step())
            except Exception:
                twin.state = previous
                raise
            return request, True
        if not 1 <= value <= 125:
            return response_frame(request, b"\x83\x03"), False
        state = self.pipeline.state_manager.snapshot()
        registers = {key: int(state[name]) for key, name in {**SENSORS, **ACTUATORS}.items()}
        if any(key not in registers for key in range(address, address + value)):
            return response_frame(request, b"\x83\x02"), False
        values = [registers[key] for key in range(address, address + value)]
        return response_frame(request, bytes([3, 2 * value]) + struct.pack(">" + "H" * value, *values)), True

    def process_request_frame(self, request, source):
        # Serialize commands, state transitions and feature windows across clients.
        with self.transaction_lock, self.pipeline._twin_lock:
            event_start = len(self.pipeline.telemetry_events)
            decision_start = len(self.pipeline.decision_history)
            enforcement_start = len(self.pipeline.enforcement_history)
            emergency_start = len(self.pipeline.twin_states)
            try:
                if not isinstance(self.pipeline.stage1_connector, NullStage1Connector):
                    self.pipeline.sync_stage1()
                twin_before = deepcopy(self.pipeline.digital_twin)
                intervention_context = None
                profile = self.pipeline.anomaly_detector.feature_source
                if (profile in ('swat-stage1', 'swat-process', 'gateway-window')
                        and len(request) == 12 and request[7] == 6):
                    register, value = struct.unpack('>HH', request[8:12])
                    if register in ACTUATORS and value in (0, 1):
                        alternative = deepcopy(twin_before)
                        alternative.apply_actions({ACTUATORS[register]: 1 - value})
                        alternative_state = alternative.step()
                        intervention_context = {
                            'alternative_state': alternative_state,
                            'known_blocked': (6, register, value) in self._blocked_commands,
                        }
                packet = PacketEvent(source[0], self.server_address[0], source[1],
                                     self.server_address[1], "tcp", len(request), datetime.now())
                packet.modbus_payload = request
                packets = self.packets_for_source(packet)
                if intervention_context is not None:
                    alternative_features = intervention_context.pop('alternative_state')
                    if profile == 'gateway-window':
                        from feature_extractor import FeatureExtractor
                        extractor = FeatureExtractor(window_seconds=self.window_seconds)
                        for observed in packets:
                            extractor.add_packet({'src_ip': observed.src_ip, 'dst_ip': observed.dst_ip,
                                                  'size': observed.size, 'timestamp': observed.timestamp})
                        alternative_features = {**alternative_features, **extractor.extract_network_features()}
                    intervention_context['alternative_score'] = self.pipeline.anomaly_detector.predict(
                        alternative_features).ensemble_score
                twin_reply, supported = self.twin_response(request)
                result = self.pipeline._process_packet_batch(
                    packets, intervention_context=intervention_context,
                    new_packet_count=1)
                self.pipeline.telemetry_events[-1].detection['window_seconds'] = self.window_seconds
                self.pipeline.telemetry_events[-1].detection['window_packet_count'] = len(packets)
                if result['decision'] == 'BLOCK' and intervention_context is not None:
                    # The candidate Twin state was used for scoring only. A
                    # withheld command must not alter the authoritative Twin.
                    self.pipeline.digital_twin.state = twin_before.state
                    self.pipeline.digital_twin._rng.setstate(twin_before._rng.getstate())
                    self.pipeline.digital_twin._inlet_override_active = twin_before._inlet_override_active
                    self.pipeline.state_manager.transition(twin_before.snapshot())
                    if result['new_attributed_rule']:
                        self._blocked_commands.add((6, register, value))
                        self.pipeline._trigger_digital_twin_response(result['detection'])
                    self.pipeline._previous_process_state = self.pipeline.state_manager.snapshot()
                    self.pipeline.telemetry_events[-1].detection['twin_commit'] = 'withheld'
                elif intervention_context is not None:
                    self.pipeline.telemetry_events[-1].detection['twin_commit'] = 'committed'
                if (self.emergency_hook is not None
                        and len(self.pipeline.twin_states) > emergency_start):
                    actions = self.pipeline.twin_states[-1]['actions']
                    delivered = self.emergency_hook(actions)
                    self.pipeline.telemetry_events[-1].detection['mock_safety_actions'] = delivered
                if not supported:
                    return twin_reply
                if result["decision"] != "ALLOW":
                    # A blocked write was never committed upstream. Returning
                    # the FC06 success echo would falsely acknowledge it.
                    if request[7] == 6:
                        return response_frame(request, b"\x86\x04")
                    return twin_reply
                reply = self.forward_allowed_request(request)
                if reply[:4] != request[:4] or reply[6] != request[6] or reply[7] not in (request[7], request[7] | 0x80):
                    raise ValueError("Upstream response does not match transaction")
                return reply
            except Exception:
                logging.exception("Gateway transaction failed; no classification bypass")
                return response_frame(request, bytes([request[7] | 0x80, 4]))
            finally:
                if self.telemetry_file:
                    try:
                        self.telemetry_file.parent.mkdir(parents=True, exist_ok=True)
                        with self.telemetry_file.open('a') as handle:
                            for event in self.pipeline.telemetry_events[event_start:]:
                                row = event.to_dict()
                                row['label'] = self.label
                                row['decision'] = (self.pipeline.decision_history[-1]['decision']
                                    if len(self.pipeline.decision_history) > decision_start else 'ERROR')
                                row['enforcement'] = self.pipeline.enforcement_history[enforcement_start:]
                                handle.write(json.dumps(row) + '\n')
                    except OSError:
                        logging.exception("Unable to persist gateway telemetry")


class GatewayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(self.server.timeout)
        while True:
            try:
                frame = receive_frame(self.request)
                self.request.sendall(self.server.process_request_frame(frame, self.client_address))
            except (EOFError, ValueError, OSError):
                return


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=5020)
    parser.add_argument("--scada-host", required=True)
    parser.add_argument("--scada-port", type=int, default=502)
    parser.add_argument("--model", required=True)
    parser.add_argument("--ensemble-only", action="store_true",
                        help="Use model ensemble without the learned actuator-value override")
    parser.add_argument("--rules-file")
    parser.add_argument("--telemetry-file")
    parser.add_argument("--deployment-config", help="Explicit pfSense SSH deployment JSON")
    parser.add_argument("--window-seconds", type=float, default=60,
                        help="Per-source trailing traffic window (default: 60 seconds)")
    args = parser.parse_args()
    pipeline = IntegrationOrchestrator(detector_model_path=args.model,
        firewall_enabled=False, snort_rules_path=args.rules_file,
        snort_blocking=True, use_actuator_support=not args.ensemble_only)
    if args.deployment_config:
        from deploy_snort_rules_ssh import configure_deployment
        configure_deployment(pipeline, args.deployment_config)
    with ModbusGateway((args.listen_host, args.listen_port),
                       (args.scada_host, args.scada_port), pipeline,
                       telemetry_file=args.telemetry_file,
                       window_seconds=args.window_seconds) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
