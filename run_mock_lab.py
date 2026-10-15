"""Explicit test-only gateway and mock SCADA; no trained-model claims."""
import argparse
import json
import math
import struct
import threading
from datetime import datetime

from mock_scada import MockScadaServer
from modbus_gateway import ModbusGateway
from orchestrator import IntegrationOrchestrator
from physics_engine import PhysicsParams
from physical_stage1 import ArduinoNanoSerialStage1Connector
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
    parser.add_argument("--plant-topology", choices=("swat", "three_tank_transfer"), default="swat",
                        help="Select SWaT simulation or the physical rig's three-box transfer topology")
    parser.add_argument("--stage1-serial", help="Arduino Nano USB serial device, e.g. /dev/ttyUSB0")
    parser.add_argument("--stage1-baud", type=int, default=115200)
    parser.add_argument("--stage1-serial-format", choices=("json", "arduino-text"), default="json",
                        help="Use arduino-text for the original Distance/Flow sketch")
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
    if args.label and not args.telemetry_file:
        parser.error("--label requires --telemetry-file")
    if args.ensemble_only and not args.model:
        parser.error("--ensemble-only requires --model")
    if args.stage1_serial and args.plant_topology != "three_tank_transfer":
        parser.error("--stage1-serial requires --plant-topology three_tank_transfer")
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
                                                   serial_format=args.stage1_serial_format)
                 if args.stage1_serial else None)
    pipeline = IntegrationOrchestrator(detector_model_path=args.model, firewall_enabled=False,
        snort_rules_path=args.rules_file, snort_blocking=True,
        use_actuator_support=not args.ensemble_only,
        physics_params=PhysicsParams(stage1_topology=args.plant_topology,
                                     stage1_auto_low_level_mm=auto_low,
                                     stage1_auto_high_level_mm=auto_high),
        stage1_connector=connector,
        stage1_sync_interval_seconds=0.5 if connector else None)
    if (args.model and args.plant_topology == "three_tank_transfer"
            and pipeline.anomaly_detector.metadata.get("plant_topology") != "three_tank_transfer"):
        parser.error("three_tank_transfer requires a calibrated model declared for that topology")
    if args.deployment_config:
        from deploy_snort_rules_ssh import configure_deployment
        print(json.dumps(configure_deployment(pipeline, args.deployment_config)), flush=True)
    with MockScadaServer(("127.0.0.1", args.scada_port)) as scada:
        thread = threading.Thread(target=scada.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            if connector:
                pipeline.start()
            gateway_class = ModbusGateway if args.model else LabGateway
            label = {"normal": 0, "attack": 1}.get(args.label)
            with gateway_class((args.listen_host, args.listen_port), scada.server_address, pipeline,
                               telemetry_file=args.telemetry_file, label=label,
                               emergency_hook=scada.apply_emergency_actions,
                               window_seconds=args.window_seconds) as gateway:
                mode = (f"MODEL MODE: {pipeline.anomaly_detector.feature_source}"
                        + (" (ensemble only)" if args.ensemble_only else "")
                        if args.model else "TEST MODE: fixed classifications, not ML accuracy.")
                print(mode, flush=True)
                print(f"Plant topology: {args.plant_topology}", flush=True)
                print("Automatic pfSense deployment enabled" if args.deployment_config else "No pfSense deployment configured", flush=True)
                print(f"Gateway {args.listen_host}:{args.listen_port}; mock SCADA 127.0.0.1:{args.scada_port}", flush=True)
                print(f"Per-source traffic window: {args.window_seconds:g} seconds", flush=True)
                try:
                    gateway.serve_forever()
                except KeyboardInterrupt:
                    pass
        finally:
            scada.shutdown()
            thread.join(timeout=2)
            if connector:
                pipeline.stop()
                connector.close()


if __name__ == "__main__":
    main()
