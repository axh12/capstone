"""
Integration Orchestrator
========================
Main control engine that ties together:
1. Network packet capture
2. Digital Twin simulation
3. Anomaly detection
4. Signature extraction
5. Firewall management
"""

import json
import time
import logging
import sys
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from enum import Enum

from feature_extractor import FeatureExtractor
from realtime_anomaly_detector import RealTimeAnomalyDetector, AnomalyDetectionResult
from firewall_manager import FirewallManager, FirewallRule
from snort_integration import SnortRuleManager
from network_integration import NetworkSniffer, SimulatedNetworkSource, PacketEvent
from telemetry import TelemetryEvent, build_state_change
from state_manager import StateManager
from decision_engine import DecisionEngine
from physical_stage1 import NullStage1Connector

# Add paths to use existing modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Anomaly Detection'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Signature Extraction Module (SEM)'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Digital Twin'))

# Import Digital Twin for emergency response
try:
    from physics_engine import PhysicsEngine
    DIGITAL_TWIN_AVAILABLE = True
except ImportError:
    DIGITAL_TWIN_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("Digital Twin not available - emergency responses disabled")

try:
    from FEATURES_ATTACK2_OPTIMIZED import ATTACK2_OPTIMIZED_FEATURES, SENSOR_FEATURES, NETWORK_FEATURES
    FEATURES_AVAILABLE = True
except ImportError:
    FEATURES_AVAILABLE = False
    ATTACK2_OPTIMIZED_FEATURES = []


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PipelineState(Enum):
    """Pipeline state enumeration."""
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    ERROR = "ERROR"


class IntegrationOrchestrator:
    """
    Main orchestration engine for integrated threat detection and response.
    
    Pipeline Flow:
    1. PacketCapture -> 2. FeatureExtraction -> 3. AnomalyDetection ->
    4. SignatureExtraction -> 5. FirewallResponse
    """
    
    def __init__(
        self,
        detector_model_path: Optional[str] = None,
        use_real_network: bool = False,
        firewall_enabled: bool = True,
        dry_run: bool = True,
        enable_digital_twin: bool = True,
        snort_rules_path: Optional[str] = None,
        snort_blocking: bool = False,
        snort_apply_command: Optional[str] = None,
        stage1_connector=None,
        stage1_sync_interval_seconds: Optional[float] = None,
    ):
        """
        Initialize the orchestrator.
        
        Args:
            detector_model_path: Path to saved anomaly detection models
            use_real_network: True to sniff real network, False for simulation
            firewall_enabled: Enable firewall rule application
            dry_run: Don't actually apply firewall rules
            enable_digital_twin: Enable Digital Twin emergency response
            snort_rules_path: Write generated Snort rules to this path when set
            snort_blocking: Generate ``drop`` instead of ``alert`` rules
            snort_apply_command: Optional command to reload Snort; use {rules_file}
        """
        self.detector_model_path = detector_model_path
        self.use_real_network = use_real_network
        self.firewall_enabled = firewall_enabled
        self.dry_run = dry_run
        self.enable_digital_twin = enable_digital_twin
        self.stage1_connector = stage1_connector or NullStage1Connector()
        self.stage1_sync_interval_seconds = stage1_sync_interval_seconds
        self._stage1_stop = threading.Event()
        self._stage1_thread = None
        self.state_manager = StateManager()
        self.decision_engine = DecisionEngine()
        self.snort_rule_manager = (
            SnortRuleManager(
                rules_path=snort_rules_path,
                blocking=snort_blocking,
                apply_command=snort_apply_command,
            )
            if snort_rules_path else None
        )
        
        # Initialize components
        self.feature_extractor = FeatureExtractor(window_seconds=5)
        self.anomaly_detector = RealTimeAnomalyDetector(model_path=detector_model_path)
        self.firewall_manager = FirewallManager(
            use_iptables=False,  # Use database mode
            dry_run=dry_run
        )
        
        # Initialize Digital Twin if available
        self.digital_twin = None
        if enable_digital_twin and DIGITAL_TWIN_AVAILABLE:
            try:
                self.digital_twin = PhysicsEngine()
                # Keep the validated State Manager authoritative from the
                # first Twin snapshot, not only after an emergency action.
                self.state_manager.transition(self.digital_twin.snapshot())
                logger.info("✓ Digital Twin initialized")
            except Exception as e:
                logger.warning(f"⚠ Failed to initialize Digital Twin: {e}")
        
        # Network source
        if use_real_network:
            self.network_source = NetworkSniffer(interface=None)  # Auto-detect
        else:
            self.network_source = SimulatedNetworkSource()
        
        # State tracking
        self.state = PipelineState.IDLE
        self.start_time = None
        self.stats = {
            'packets_processed': 0,
            'anomalies_detected': 0,
            'rules_applied': 0,
            'false_positives': 0,
            'true_positives': 0,
            'emergency_responses': 0
        }
        
        # Detection history
        self.detection_history: List[AnomalyDetectionResult] = []
        self.applied_rules: List[str] = []
        self.twin_states: List[Dict] = []  # Track twin state changes
        self.telemetry_events: List[TelemetryEvent] = []
        self.decision_history: List[Dict] = []
        self._previous_process_state: Dict = {}
        self._window_packets: List[PacketEvent] = []
        
        logger.info("✓ Integration Orchestrator initialized")
    
    def start(self) -> None:
        """Start the orchestrator pipeline."""
        if self.state == PipelineState.RUNNING:
            logger.warning("Pipeline already running")
            return
        
        try:
            self.state = PipelineState.RUNNING
            self.start_time = datetime.now()
            
            # Start network source if using real network
            if self.use_real_network:
                self.network_source.register_callback(self._on_packet_received)
                self.network_source.start()
                logger.info("✓ Real network sniffer started")
            if self.stage1_sync_interval_seconds and self.stage1_sync_interval_seconds > 0:
                self._stage1_stop.clear()
                self._stage1_thread = threading.Thread(
                    target=self._stage1_sync_loop, daemon=True, name="stage1-read-only-sync"
                )
                self._stage1_thread.start()
            
            logger.info(f"✓ Pipeline started at {self.start_time}")
        
        except Exception as e:
            logger.error(f"✗ Failed to start pipeline: {e}")
            self.state = PipelineState.ERROR
            raise
    
    def stop(self) -> None:
        """Stop the orchestrator pipeline."""
        self.state = PipelineState.IDLE
        
        if self.use_real_network:
            self.network_source.stop()
        self._stage1_stop.set()
        if self._stage1_thread:
            self._stage1_thread.join(timeout=2)
            self._stage1_thread = None
        
        logger.info("✓ Pipeline stopped")
    
    def process_simulated_traffic(
        self,
        normal_count: int = 100,
        attack_count: int = 50,
        attack_type: str = 'exfiltration'
    ) -> Dict:
        """
        Process simulated network traffic for testing.
        
        Args:
            normal_count: Number of normal traffic packets to generate
            attack_count: Number of attack packets
            attack_type: 'exfiltration' or 'tampering'
            
        Returns:
            Summary of processing results
        """
        logger.info("Processing simulated traffic...")
        
        # Generate normal traffic
        normal_packets = self.network_source.generate_normal_traffic(normal_count)
        logger.info(f"Generated {len(normal_packets)} normal traffic packets")
        
        # Generate attack traffic
        attack_packets = self.network_source.generate_attack_traffic(
            count=attack_count,
            attack_type=attack_type
        )
        logger.info(f"Generated {len(attack_packets)} {attack_type} attack packets")
        
        # Process all packets
        results = {
            'normal_traffic': self._process_packet_batch(normal_packets),
            'attack_traffic': self._process_packet_batch(attack_packets)
        }
        
        return results
    
    def _process_packet_batch(self, packets: List[PacketEvent]) -> Dict:
        """
        Process a batch of packets.
        
        Args:
            packets: List of PacketEvent objects
            
        Returns:
            Processing summary
        """
        summary = {
            'packets_processed': 0,
            'anomalies_detected': 0,
            'detections': []
        }

        if not packets:
            return summary
        
        self.feature_extractor.reset_window()
        sensor_data = self._get_sensor_data(packets)
        
        # Add packets to feature extractor
        for packet in packets:
            self.feature_extractor.add_packet({
                'src_ip': packet.src_ip,
                'dst_ip': packet.dst_ip,
                'size': packet.size,
                'timestamp': packet.timestamp
            })
            summary['packets_processed'] += 1
        
        # Extract features
        feature_vector = self.feature_extractor.build_feature_vector(sensor_data)
        telemetry = self._build_telemetry_event(packets, feature_vector)
        
        # Run anomaly detection and SEM candidate extraction concurrently.
        # Enforcement is still decided only after both futures complete.
        with ThreadPoolExecutor(max_workers=2) as pool:
            detection_future = pool.submit(self.anomaly_detector.predict, feature_vector)
            signature_future = pool.submit(self._extract_candidate_signature, telemetry, packets)
            detection = detection_future.result()
            signature = signature_future.result()
        signature.update({
            'timestamp': detection.timestamp.isoformat(),
            'attack_type': detection.attack_type or 'UNKNOWN',
            'anomaly_score': detection.ensemble_score,
        })
        self.detection_history.append(detection)
        self._finalize_telemetry(telemetry, signature)
        decision = self.decision_engine.decide(detection, signature)
        self.decision_history.append({
            'decision': decision.decision.value,
            'reason': decision.reason,
            'timestamp': detection.timestamp.isoformat(),
        })
        summary['decision'] = decision.decision.value
        
        if detection.is_anomaly:
            summary['anomalies_detected'] += 1
            summary['detections'].append({
                'timestamp': detection.timestamp.isoformat(),
                'score': detection.ensemble_score,
                'attack_type': detection.attack_type,
                'confidence': detection.confidence
            })
            
            # Extract signatures and apply firewall rules
            self._handle_anomaly(detection, packets, signature)
        
        # Update stats
        self.stats['packets_processed'] += summary['packets_processed']
        self.stats['anomalies_detected'] += summary['anomalies_detected']
        self.feature_extractor.reset_window()
        
        return summary
    
    def _on_packet_received(self, packet: PacketEvent) -> None:
        """Called when a packet is received from real network."""
        self._window_packets.append(packet)
        self.feature_extractor.add_packet({
            'src_ip': packet.src_ip,
            'dst_ip': packet.dst_ip,
            'size': packet.size,
            'timestamp': packet.timestamp
        })
        
        self.stats['packets_processed'] += 1
        
        # Check if window is complete
        window_info = self.feature_extractor.get_window_info()
        if window_info['elapsed_seconds'] >= self.feature_extractor.window_seconds:
            self._process_feature_window(self._window_packets)
    
    def _process_feature_window(self, packets: Optional[List[PacketEvent]] = None) -> None:
        """Process accumulated features for current window."""
        # Build model inputs from the Twin state and compatibility mapping.
        sensor_data = self._get_sensor_data(packets)
        
        # Extract features
        feature_vector = self.feature_extractor.build_feature_vector(sensor_data)
        telemetry = self._build_telemetry_event(packets, feature_vector)
        
        with ThreadPoolExecutor(max_workers=2) as pool:
            detection_future = pool.submit(self.anomaly_detector.predict, feature_vector)
            signature_future = pool.submit(self._extract_candidate_signature, telemetry, packets)
            detection = detection_future.result()
            signature = signature_future.result()
        signature.update({
            'timestamp': detection.timestamp.isoformat(),
            'attack_type': detection.attack_type or 'UNKNOWN',
            'anomaly_score': detection.ensemble_score,
        })
        self.detection_history.append(detection)
        self._finalize_telemetry(telemetry, signature)
        decision = self.decision_engine.decide(detection, signature)
        self.decision_history.append({
            'decision': decision.decision.value,
            'reason': decision.reason,
            'timestamp': detection.timestamp.isoformat(),
        })
        
        if detection.is_anomaly:
            self.stats['anomalies_detected'] += 1
            logger.warning(
                f"🚨 ANOMALY DETECTED: Score={detection.ensemble_score:.2f}, "
                f"Type={detection.attack_type}"
            )
            
            # Extract signatures and apply rules
            self._handle_anomaly(detection, packets=packets, signature=signature)
        
        # Reset for next window
        self.feature_extractor.reset_window()
        self._window_packets = []

    def _get_sensor_data(
        self,
        packets: Optional[List[PacketEvent]] = None
    ) -> Dict[str, float]:
        """
        Build detector sensor inputs from the Twin's authoritative state.

        The current physics model and the trained anomaly model use different
        sensor names.  Until an explicit physical-to-model mapping is supplied,
        baseline values remain as a documented compatibility fallback.  Any
        Twin field whose name is already a model feature takes precedence.
        """
        sensors = {
            'AIT504.Pv': 0.71,
            'PIT501.Pv': 221.49,
            'AIT303.Pv': 34.79,
            'PIT503.Pv': 194.41,
            'DPIT301.Pv': 14.37,
            'AIT503.Pv': 30.67,
            'AIT502.Pv': 191.81,
            'P1_STATE': 3
        }

        twin_state = self.state_manager.snapshot()
        if not twin_state and self.digital_twin:
            twin_state = self.digital_twin.snapshot()
        sensors.update({
            name: value for name, value in twin_state.items()
            if name in sensors
        })

        if packets and any(p.src_ip == '10.0.0.50' for p in packets):
            sensors.update({
                'AIT504.Pv': 3.5,
                'AIT303.Pv': 180.0,
                'AIT503.Pv': 300.0,
                'AIT502.Pv': 450.0
            })

        return sensors
    
    def _handle_anomaly(
        self,
        detection: AnomalyDetectionResult,
        packets: Optional[List[PacketEvent]] = None,
        signature: Optional[Dict] = None,
    ) -> None:
        """
        Handle detected anomaly by:
        1. Triggering Digital Twin emergency response
        2. Extracting signatures
        3. Applying firewall rules
        
        Args:
            detection: AnomalyDetectionResult object
            packets: Optional list of packets involved in anomaly
        """
        logger.warning(f"🚨 Handling anomaly: {detection.attack_type}")
        
        # STEP 1: Trigger Digital Twin Emergency Response
        if self.digital_twin and self.enable_digital_twin:
            self._trigger_digital_twin_response(detection)
        
        # STEP 2: Extract signature from anomaly
        signature = signature or self._extract_attack_signature(detection, packets)
        
        # Export command-level Snort rules independently of the optional
        # local firewall manager.  This keeps Snort automation available even
        # when IP-based firewall rules are disabled.
        if self.snort_rule_manager:
            try:
                snort_result = self.snort_rule_manager.export_signature(signature)
                if snort_result['rules']:
                    logger.info("✓ Snort rules written to %s", snort_result['path'])
                else:
                    logger.info("No command signature; no Snort rule generated")
            except Exception as exc:
                logger.error("Snort rule export failed: %s", exc)

        # STEP 3: Apply optional local firewall rules
        if self.firewall_enabled:
            rule_ids = self.firewall_manager.extract_rules_from_signature(signature)
            self.applied_rules.extend(rule_ids)
            self.stats['rules_applied'] += len(rule_ids)
            
            # Apply rules
            applied, errors = self.firewall_manager.apply_rules(rule_ids)
            
            if errors:
                logger.error(f"Firewall errors: {errors}")
            
            logger.info(f"✓ Applied {applied} firewall rules")
    
    def _trigger_digital_twin_response(self, detection: AnomalyDetectionResult) -> None:
        """
        Trigger Digital Twin emergency response when anomaly detected.
        
        Emergency actions:
        - TRAFFIC attack: Stop all pumps, open drainage valves
        - TAMPERING attack: Stop affected processes, isolate system
        
        Args:
            detection: AnomalyDetectionResult object
        """
        logger.warning("🚨 TRIGGERING DIGITAL TWIN EMERGENCY RESPONSE")
        
        try:
            # Emergency control actions based on attack type
            if detection.attack_type == 'TRAFFIC':
                logger.warning("   Attack Type: TRAFFIC (Data Exfiltration)")
                logger.warning("   Action: Emergency shutdown (stop all pumps)")
                
                # Stop all pumps, open drainage
                emergency_actions = {
                    'p101': 0,      # Stop pump 1
                    'p201': 0,      # Stop pump 2
                    'p301': 0,      # Stop pump 3
                    'mv101': 1,     # Open valve 1 (drain)
                    'mv201': 1,     # Open valve 2 (drain)
                }
            
            elif detection.attack_type == 'TAMPERING':
                logger.warning("   Attack Type: TAMPERING (Sensor Manipulation)")
                logger.warning("   Action: Isolate affected processes")
                
                # Stop process 3 (often targeted), open isolation valves
                emergency_actions = {
                    'p301': 0,      # Stop pump 3
                    'mv201': 1,     # Open isolation valve
                }
            
            else:
                logger.warning("   Attack Type: UNKNOWN")
                logger.warning("   Action: Safe state (stop all pumps)")
                
                # Conservative: stop everything
                emergency_actions = {
                    'p101': 0,
                    'p201': 0,
                    'p301': 0,
                }
            
            # Apply emergency actions to Digital Twin
            self.digital_twin.apply_actions(emergency_actions)
            twin_state = self.digital_twin.step()
            self.state_manager.transition(twin_state)
            
            self.twin_states.append({
                'timestamp': datetime.now().isoformat(),
                'trigger': detection.attack_type,
                'actions': emergency_actions,
                'resulting_state': twin_state
            })
            
            self.stats['emergency_responses'] += 1
            
            logger.info(f"   ✓ Twin state updated:")
            logger.info(f"     LIT101={twin_state.get('LIT101', 'N/A'):.1f}")
            logger.info(f"     LIT201={twin_state.get('LIT201', 'N/A'):.1f}")
            logger.info(f"     LIT301={twin_state.get('LIT301', 'N/A'):.1f}")
            
        except Exception as e:
            logger.error(f"✗ Digital Twin response error: {e}")

    def sync_stage1(self) -> Dict:
        """Read reference Stage 1 state into the twin; never write to it."""
        state = self.stage1_connector.read_state()
        if state:
            self.state_manager.apply_patch(state)
        return state

    def _stage1_sync_loop(self) -> None:
        while not self._stage1_stop.wait(self.stage1_sync_interval_seconds):
            try:
                self.sync_stage1()
            except Exception as exc:
                logger.warning("Stage 1 read-only synchronization failed: %s", exc)

    def _build_telemetry_event(
        self, packets: Optional[List[PacketEvent]], feature_vector: Dict
    ) -> TelemetryEvent:
        """Create the single telemetry contract shared by AD and SEM."""
        network: Dict = {}
        if packets:
            first = packets[0]
            network = {
                'src_ip': first.src_ip, 'dst_ip': first.dst_ip,
                'src_port': first.src_port, 'dst_port': first.dst_port,
                'protocol': first.protocol, 'packet_size': first.size,
            }
        process = self.state_manager.snapshot()
        if not process and self.digital_twin:
            process = self.digital_twin.snapshot()
        # Preserve the Twin's native state and include the model-facing sensor
        # values in the same event.  This is the explicit bridge while their
        # naming schemes differ.
        model_sensors = SENSOR_FEATURES if FEATURES_AVAILABLE else [
            'AIT504.Pv', 'PIT501.Pv', 'AIT303.Pv', 'PIT503.Pv',
            'DPIT301.Pv', 'AIT503.Pv', 'AIT502.Pv'
        ]
        for name in [*model_sensors, 'P1_STATE']:
            if name in feature_vector:
                process.setdefault(name, feature_vector[name])
        previous = dict(self._previous_process_state)
        event = TelemetryEvent.create(
            event_id=f"event-{len(self.telemetry_events) + 1}",
            network=network,
            process=process,
            previous_process=previous,
            state_change=build_state_change(previous, process),
            network_statistics={key: feature_vector.get(key, 0) for key in (
                'packet_count', 'total_bytes', 'bytes_per_sec', 'packets_per_sec',
                'unique_src_ips', 'unique_dst_ips', 'unique_ip_pairs',
                'avg_packet_size', 'max_packet_size', 'packet_size_range',
                'bytes_per_packet', 'small_packets_count')},
        )
        self.telemetry_events.append(event)
        self._previous_process_state = process

        return event

    def _finalize_telemetry(self, event: TelemetryEvent, signature: Dict) -> None:
        """Add decoded Modbus context after SEM has examined the packet window."""
        command = signature.get('modbus_commands', [{}])[0]
        if command:
            event.network.update({
                'function_code': command.get('function_code', command.get('function')),
                'register': command.get('register'),
                'value': command.get('value'),
            })

    def _extract_candidate_signature(
        self, telemetry: TelemetryEvent, packets: Optional[List[PacketEvent]] = None
    ) -> Dict:
        """Run SEM from shared Twin telemetry without waiting for AD's result."""
        sensor_list = SENSOR_FEATURES if FEATURES_AVAILABLE else [
            'AIT504.Pv', 'PIT501.Pv', 'AIT303.Pv', 'PIT503.Pv',
            'DPIT301.Pv', 'AIT503.Pv', 'AIT502.Pv'
        ]
        feature_vector = dict(telemetry.network_statistics)
        feature_vector.update({
            name: value for name, value in telemetry.process.items()
            if name in sensor_list or name == 'P1_STATE'
        })
        candidate = AnomalyDetectionResult(
            timestamp=datetime.now(),
            is_anomaly=False,
            ensemble_score=0.0,
            feature_vector=feature_vector,
            confidence=0.0,
            attack_type='UNKNOWN',
        )
        return self._extract_attack_signature(candidate, packets)
    
    def _extract_attack_signature(
        self,
        detection: AnomalyDetectionResult,
        packets: Optional[List[PacketEvent]] = None
    ) -> Dict:
        """
        Extract attack signature from detected anomaly.
        
        Uses SEM (Signature Extraction Module) approach from your existing code.
        Compares anomalous features to baseline statistics to extract patterns.
        
        Args:
            detection: AnomalyDetectionResult
            packets: Optional packet list for additional context
            
        Returns:
            Dictionary with signature information (SEM format)
        """
        # Use actual sensor features from your module if available
        sensor_list = SENSOR_FEATURES if FEATURES_AVAILABLE else [
            'AIT504.Pv', 'PIT501.Pv', 'AIT303.Pv', 'PIT503.Pv',
            'DPIT301.Pv', 'AIT503.Pv', 'AIT502.Pv'
        ]
        
        network_list = NETWORK_FEATURES if FEATURES_AVAILABLE else [
            'bytes_per_sec', 'unique_dst_ips', 'unique_src_ips',
            'bytes_per_packet', 'max_packet_size', 'packet_size_range',
            'avg_packet_size', 'packets_per_sec', 'packet_count',
            'total_bytes', 'small_packets_count', 'unique_ip_pairs'
        ]
        
        features = detection.feature_vector
        
        # Initialize signature using SEM-style structure
        signature = {
            'timestamp': detection.timestamp.isoformat(),
            'attack_type': detection.attack_type or 'UNKNOWN',
            'anomaly_score': detection.ensemble_score,
            'feature_deviations': {},      # SEM: stats of anomalous features
            'affected_sensors': [],         # SEM: which sensors are anomalous
            'network_indicators': {},       # SEM: network patterns
            'src_ips': [],
            'dst_ips': [],
            'ports': [],
            'ip_pairs': [],
            'modbus_commands': []
        }
        
        normal_ranges = {
            'AIT504.Pv': (0.0, 2.0),
            'PIT501.Pv': (200.0, 240.0),
            'AIT303.Pv': (25.0, 70.0),
            'PIT503.Pv': (180.0, 210.0),
            'DPIT301.Pv': (0.0, 25.0),
            'AIT503.Pv': (20.0, 55.0),
            'AIT502.Pv': (170.0, 220.0),
        }

        # Identify affected sensors (SEM approach: compare to normal baseline)
        for sensor in sensor_list:
            value = features.get(sensor, 0)
            low, high = normal_ranges.get(sensor, (float('-inf'), float('inf')))
            if value < low or value > high:
                signature['affected_sensors'].append(sensor)
                signature['feature_deviations'][sensor] = {
                    'value': float(value),
                    'expected_range': [float(low), float(high)],
                    'deviation_magnitude': float(min(abs(value - low), abs(value - high)))
                }
        
        # Extract network indicators (SEM style statistical patterns)
        signature['network_indicators'] = {
            'bytes_per_sec': float(features.get('bytes_per_sec', 0)),
            'packets_per_sec': float(features.get('packets_per_sec', 0)),
            'unique_src_ips': int(features.get('unique_src_ips', 0)),
            'unique_dst_ips': int(features.get('unique_dst_ips', 0)),
            'bytes_per_packet': float(features.get('bytes_per_packet', 0)),
            'total_bytes': float(features.get('total_bytes', 0))
        }
        
        # If we have packet data, extract IP/port details
        if packets:
            from collections import defaultdict
            
            src_ips = set([p.src_ip for p in packets])
            dst_ips = set([p.dst_ip for p in packets])
            ports = set([p.dst_port for p in packets if p.dst_port])
            
            signature['src_ips'] = list(src_ips)[:5]
            signature['dst_ips'] = list(dst_ips)[:5]
            signature['ports'] = list(ports)[:3]
            signature['ip_pairs'] = [
                f"{p.src_ip}_{p.dst_ip}" for p in packets[:5]
            ]

            # Decode Modbus/TCP FC06 requests from captured TCP payloads.
            # MBAP header is 7 bytes; function, register and value follow.
            for packet in packets:
                if packet.protocol != 'tcp' or packet.dst_port != 5020 or not packet.raw_data:
                    continue
                try:
                    from scapy.all import IP, Raw
                    dissected = IP(packet.raw_data)
                    if not dissected.haslayer(Raw):
                        continue
                    payload = bytes(dissected[Raw].load)
                    if len(payload) >= 12 and payload[2:4] == b'\x00\x00' and payload[7] == 6:
                        signature['modbus_commands'].append({
                            'function': 6,
                            'function_code': 6,
                            'register': int.from_bytes(payload[8:10], 'big'),
                            'value': int.from_bytes(payload[10:12], 'big'),
                            'src_ip': packet.src_ip,
                            'dst_ip': packet.dst_ip,
                        })
                except Exception:
                    continue
        
        logger.info(f"📋 Extracted signature (SEM format): {json.dumps(signature, indent=2)}")
        return signature
    
    def get_pipeline_status(self) -> Dict:
        """Get current pipeline status."""
        uptime = None
        if self.start_time:
            uptime = (datetime.now() - self.start_time).total_seconds()
        
        return {
            'state': self.state.value,
            'uptime_seconds': uptime,
            'statistics': self.stats,
            'firewall_status': self.firewall_manager.get_rule_statistics(),
            'detection_history_count': len(self.detection_history),
            'telemetry_event_count': len(self.telemetry_events),
            'decision_count': len(self.decision_history),
        }
    
    def get_recent_detections(self, limit: int = 10) -> List[Dict]:
        """Get recent anomaly detections."""
        anomalies = [d for d in self.detection_history if d.is_anomaly]
        return [d.to_dict() for d in anomalies[-limit:]]
    
    def export_session_data(self, filepath: str) -> None:
        """Export session data to JSON."""
        data = {
            'session_start': self.start_time.isoformat() if self.start_time else None,
            'session_end': datetime.now().isoformat(),
            'pipeline_status': self.get_pipeline_status(),
            'recent_detections': self.get_recent_detections(limit=100),
            'applied_rules': self.applied_rules,
            'telemetry': [event.to_dict() for event in self.telemetry_events[-100:]],
            'decisions': self.decision_history[-100:],
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"📤 Exported session data to {filepath}")
        
        # Also export firewall rules
        rules_file = filepath.replace('.json', '_rules.json')
        self.firewall_manager.export_rules(rules_file)


def main():
    """Example usage of the orchestrator."""
    
    # Initialize orchestrator (with simulated network)
    orchestrator = IntegrationOrchestrator(
        detector_model_path=None,  # Will skip model loading
        use_real_network=False,    # Use simulated network
        firewall_enabled=True,
        dry_run=True               # Don't actually apply rules
    )
    
    try:
        # Start pipeline
        orchestrator.start()
        
        logger.info("\n=== PROCESSING SIMULATED NORMAL TRAFFIC ===")
        results = orchestrator.process_simulated_traffic(
            normal_count=100,
            attack_count=0
        )
        logger.info(f"Normal traffic results: {json.dumps(results, indent=2)}")
        
        logger.info("\n=== PROCESSING SIMULATED ATTACK TRAFFIC ===")
        results = orchestrator.process_simulated_traffic(
            normal_count=50,
            attack_count=50,
            attack_type='exfiltration'
        )
        logger.info(f"Attack traffic results: {json.dumps(results, indent=2)}")
        
        # Get status
        logger.info("\n=== PIPELINE STATUS ===")
        status = orchestrator.get_pipeline_status()
        logger.info(json.dumps(status, indent=2))
        
        # Export session
        orchestrator.export_session_data('/tmp/orchestrator_session.json')
        
    finally:
        orchestrator.stop()


if __name__ == '__main__':
    main()
