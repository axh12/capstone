"""Explicit test-only gateway and mock SCADA; no trained-model claims."""
import argparse
import json
import math
import struct
import threading
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime

from mock_scada import MockScadaServer
from modbus_gateway import ModbusGateway
from orchestrator import IntegrationOrchestrator
from physics_engine import PhysicsParams
from physical_stage1 import ArduinoNanoSerialStage1Connector, ArduinoNanoModbusForwarder
from realtime_anomaly_detector import AnomalyDetectionResult


class LabGateway(ModbusGateway):
    def process_request_frame(self, request, source):
        with self.transaction_lock:
            # A repeatable fixture exercises both architecture branches.
            # FC06 register 20 value 1 is the designated test attack.
            blocked = (self.pipeline.digital_twin.params.stage1_topology == 'swat'
                       and len(request) == 12 and request[7] == 6
                       and struct.unpack(">HH", request[8:12]) == (20, 1))
            self.pipeline.anomaly_detector.predict = lambda features: AnomalyDetectionResult(
                datetime.now(), blocked, 0.9 if blocked else 0.01, features,
                0.8, "LAB_FIXTURE" if blocked else None)
            reply = super().process_request_frame(request, source)
            print(json.dumps({"component": "LAB_GATEWAY", "source": source[0],
                              "fixture_decision": "BLOCK" if blocked else "ALLOW",
                              "request": request.hex(), "reply": reply.hex()}), flush=True)
            return reply


def rig_fill_thresholds(empty_distance_mm, serial_format, low_mm, high_mm):
    """Optionally convert the Nano's 8/2 cm points when a depth reference exists."""
    if serial_format == 'arduino-text' and empty_distance_mm is not None:
        if not math.isfinite(empty_distance_mm):
            raise ValueError('Invalid --empty-distance-mm')
        if empty_distance_mm < 80:
            raise ValueError('Empty-box sensor distance must be at least 80 mm')
        derived_low = empty_distance_mm - 80
        derived_high = empty_distance_mm - 20
        if low_mm is not None and not math.isclose(low_mm, derived_low):
            raise ValueError('--auto-fill-low-mm conflicts with Arduino 8 cm switch point')
        if high_mm is not None and not math.isclose(high_mm, derived_high):
            raise ValueError('--auto-fill-high-mm conflicts with Arduino 2 cm switch point')
        return derived_low, derived_high
    return (500.0 if low_mm is None else low_mm,
            800.0 if high_mm is None else high_mm)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=5020)
    parser.add_argument("--scada-port", type=int, default=15020)
    parser.add_argument("--rules-file", default="/tmp/capstone-lab.rules")
    parser.add_argument("--model", help="Use a trained supported model instead of fixed classifications")
    parser.add_argument('--swat-profile', help='Normal-training SWaT physics profile from swat_mock_profile.py')
    parser.add_argument('--stage1-guards', action='store_true',
                        help='Enable explicit 60-second forecast, overflow and sensor-residual guards')
    parser.add_argument("--plant-topology", choices=("swat", "swat_stage1", "three_tank_transfer"), default="swat",
                        help="Select SWaT simulation or the physical rig's three-box transfer topology")
    parser.add_argument("--stage1-serial", help="Arduino Nano USB serial device, e.g. /dev/ttyUSB0")
    parser.add_argument("--stage1-baud", type=int, default=115200)
    parser.add_argument("--stage1-serial-format", choices=("json", "arduino-text"), default="json",
                        help="Use arduino-text for the original Distance/Flow sketch")
    parser.add_argument("--stage1-probe", action="store_true",
                        help="Read five live Nano samples into the Twin and exit without starting a gateway")
    parser.add_argument("--physical-forward", action="store_true",
                        help="Forward allowed pump-1 writes to the Nano instead of starting mock SCADA")
    parser.add_argument("--empty-distance-mm", type=float,
                        help="Distance sensor reading in millimetres when box 2 is empty")
    parser.add_argument("--auto-fill-low-mm", type=float,
                        help="Box-2 level that turns pump 1 on in rig simulation (provisional default: 500 mm)")
    parser.add_argument("--auto-fill-high-mm", type=float,
                        help="Box-2 level that turns pump 1 off in rig simulation (provisional default: 800 mm)")
    parser.add_argument("--ensemble-only", action="store_true",
                        help="Use model ensemble without the learned actuator-value override")
    parser.add_argument("--deployment-config", help="Enable explicit pfSense SSH deployment")
    parser.add_argument("--telemetry-file", help="Append transaction telemetry JSONL")
    parser.add_argument("--window-seconds", type=float, default=60,
                        help="Per-source trailing traffic window (default: 60 seconds)")
    parser.add_argument("--label", choices=("normal", "attack"), help="Human scenario label for recorded data, never inferred from decisions")
    args = parser.parse_args()
    if args.stage1_guards and args.plant_topology != 'swat_stage1':
        parser.error('--stage1-guards requires --plant-topology swat_stage1')
    if args.swat_profile and (not args.model or args.plant_topology != 'swat_stage1'
                              or args.stage1_serial or args.physical_forward):
        parser.error('--swat-profile requires a model and --plant-topology swat_stage1')
    if args.plant_topology == 'swat_stage1' and not args.swat_profile:
        parser.error('swat_stage1 requires --swat-profile and its matching --model')
    if args.label and not args.telemetry_file:
        parser.error("--label requires --telemetry-file")
    if args.ensemble_only and not args.model:
        parser.error("--ensemble-only requires --model")
    if args.stage1_serial and args.plant_topology != "three_tank_transfer":
        parser.error("--stage1-serial requires --plant-topology three_tank_transfer")
    if args.stage1_probe and not args.stage1_serial:
        parser.error("--stage1-probe requires --stage1-serial")
    if args.physical_forward and (not args.stage1_serial or not args.model):
        parser.error("--physical-forward requires --stage1-serial and a rig-calibrated --model")
    if args.physical_forward and args.stage1_probe:
        parser.error("--physical-forward cannot be combined with --stage1-probe")
    if args.physical_forward and (args.stage1_serial_format != 'arduino-text' or args.stage1_baud != 9600):
        parser.error("--physical-forward requires the updated 9600-baud arduino-text Nano sketch")
    try:
        auto_low, auto_high = rig_fill_thresholds(
            args.empty_distance_mm,
            args.stage1_serial_format if args.stage1_serial else 'json',
            args.auto_fill_low_mm, args.auto_fill_high_mm)
    except ValueError as error:
        parser.error(str(error))
    if args.plant_topology == "three_tank_transfer" and not (
            0 <= auto_low < auto_high <= 1200):
        parser.error("rig fill thresholds must satisfy 0 <= low < high <= 1200 mm")
    if args.model and args.plant_topology == "three_tank_transfer" and not args.ensemble_only:
        parser.error("three_tank_transfer model mode requires --ensemble-only")
    connector = (ArduinoNanoSerialStage1Connector(args.stage1_serial, args.empty_distance_mm,
                                                   baudrate=args.stage1_baud,
                                                   timeout_seconds=1.5,
                                                   serial_format=args.stage1_serial_format)
                 if args.stage1_serial else None)
    pipeline = IntegrationOrchestrator(detector_model_path=args.model, firewall_enabled=False,
        snort_rules_path=args.rules_file, snort_blocking=True,
        use_actuator_support=not args.ensemble_only,
        physics_params=PhysicsParams(stage1_topology=args.plant_topology,
                                     stage1_auto_low_level_mm=auto_low,
                                     stage1_auto_high_level_mm=auto_high),
        stage1_connector=connector,
        stage1_sync_interval_seconds=1.0 if connector else None)
    if (args.model and args.plant_topology == "three_tank_transfer"
            and pipeline.anomaly_detector.metadata.get("plant_topology") != "three_tank_transfer"):
        parser.error("three_tank_transfer requires a calibrated model declared for that topology")
    if args.swat_profile:
        from swat_mock_profile import load_profile
        pipeline.digital_twin.params = load_profile(args.swat_profile, pipeline.anomaly_detector)
    if args.stage1_probe:
        try:
            valid_samples = 0
            for sample in range(1, 6):
                try:
                    measured = pipeline.sync_stage1()
                except (ValueError, TimeoutError) as error:
                    print(json.dumps({"sample": sample, "valid": False,
                                      "error": str(error)}), flush=True)
                    continue
                valid_samples += 1
                print(json.dumps({"sample": sample, "valid": True,
                                  "measured": measured,
                                  "twin_state": pipeline.state_manager.snapshot(),
                                  "simulated_next_state": deepcopy(pipeline.digital_twin).step()}),
                      flush=True)
            print(json.dumps({"valid_samples": valid_samples, "total_samples": 5}), flush=True)
        finally:
            connector.close()
        return
    if args.deployment_config:
        from deploy_snort_rules_ssh import configure_deployment
        print(json.dumps(configure_deployment(pipeline, args.deployment_config)), flush=True)
    with ExitStack() as stack:
        scada = None if args.physical_forward else stack.enter_context(
            MockScadaServer(("127.0.0.1", args.scada_port)))
        thread = None
        if scada is not None:
            thread = threading.Thread(target=scada.serve_forever,
                                      kwargs={"poll_interval": 0.05}, daemon=True)
            thread.start()
        try:
            if connector:
                pipeline.start()
            gateway_class = ModbusGateway if args.model else LabGateway
            label = {"normal": 0, "attack": 1}.get(args.label)
            forwarder = ArduinoNanoModbusForwarder(connector) if args.physical_forward else None
            upstream = None if scada is None else scada.server_address
            with gateway_class((args.listen_host, args.listen_port), upstream, pipeline,
                               telemetry_file=args.telemetry_file, label=label,
                               emergency_hook=scada.apply_emergency_actions if scada else None,
                               window_seconds=args.window_seconds,
                               forwarder=forwarder, stage1_guards=args.stage1_guards) as gateway:
                if scada is not None and args.swat_profile:
                    scada.initialize_plant(pipeline.digital_twin)
                mode = (f"MODEL MODE: {pipeline.anomaly_detector.feature_source}"
                        + (" (ensemble only)" if args.ensemble_only else "")
                        if args.model else "TEST MODE: fixed classifications, not ML accuracy.")
                print(mode, flush=True)
                if args.stage1_guards:
                    print('HYBRID GUARDS: 60-second forecast; overflow prevention; sensor residual limits 5 mm / 0.1 m3/h', flush=True)
                print(f"Plant topology: {args.plant_topology}", flush=True)
                if args.swat_profile:
                    print(f'SWaT-calibrated mock physics: {args.swat_profile}', flush=True)
                print("Automatic pfSense deployment enabled" if args.deployment_config else "No pfSense deployment configured", flush=True)
                downstream = ("Nano pump 1 over serial (pump 2 manual)" if args.physical_forward
                              else f"mock SCADA 127.0.0.1:{args.scada_port}")
                print(f"Gateway {args.listen_host}:{args.listen_port}; {downstream}", flush=True)
                print(f"Per-source traffic window: {args.window_seconds:g} seconds", flush=True)
                try:
                    gateway.serve_forever()
                except KeyboardInterrupt:
                    pass
        finally:
            if scada is not None:
                scada.shutdown()
                thread.join(timeout=2)
            if connector:
                pipeline.stop()
                connector.close()


if __name__ == "__main__":
    main()
