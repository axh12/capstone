#!/usr/bin/env python3
"""Run the real-time detector with automatic Snort-rule export."""

import argparse
import time

from orchestrator import IntegrationOrchestrator
from physical_stage1 import ModbusReadOnlyStage1Connector


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="anomaly_detection_ensemble.pkl")
    parser.add_argument("--threshold", type=float, default=None,
                        help="Override anomaly threshold (use 0 only for a lab pipeline test)")
    parser.add_argument("--interface", default=None, help="Capture interface (auto-detect if omitted)")
    parser.add_argument("--rules", default="snort_custom.rules", help="Output custom.rules path")
    parser.add_argument("--block", action="store_true", help="Generate drop rules (default: alert rules)")
    parser.add_argument("--local-firewall", action="store_true",
                        help="Also create legacy local firewall rules (disabled by default)")
    parser.add_argument("--apply-command", default=None, help="Explicit reload wrapper; {rules_file} is replaced")
    parser.add_argument("--stage1-host", default=None, help="Optional read-only Stage-1 Modbus host")
    parser.add_argument("--stage1-port", type=int, default=502)
    parser.add_argument("--stage1-interval", type=float, default=None)
    args = parser.parse_args()

    # NetworkSniffer currently auto-detects the interface.  Keep this runner
    # intentionally small and safe; interface selection can be supplied by
    # the project configuration when deploying on a dedicated sensor host.
    stage1 = (ModbusReadOnlyStage1Connector(args.stage1_host, args.stage1_port)
              if args.stage1_host else None)
    orchestrator = IntegrationOrchestrator(
        detector_model_path=args.model,
        use_real_network=True,
        firewall_enabled=args.local_firewall,
        dry_run=True,
        snort_rules_path=args.rules,
        snort_blocking=args.block,
        snort_apply_command=args.apply_command,
        stage1_connector=stage1,
        stage1_sync_interval_seconds=args.stage1_interval,
    )
    if args.interface and hasattr(orchestrator.network_source, "interface"):
        orchestrator.network_source.interface = args.interface
    if args.threshold is not None:
        orchestrator.anomaly_detector.set_threshold(args.threshold)
    try:
        orchestrator.start()
        print("Monitoring traffic. Press Ctrl+C to stop.")
        while True:
            orchestrator.get_pipeline_status()
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        orchestrator.stop()


if __name__ == "__main__":
    main()
