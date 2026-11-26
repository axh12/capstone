#!/usr/bin/env python3
"""Safe command-line bridge for the physical Arduino pump controller."""
import argparse

from physical_stage1 import ArduinoSerialStage1Connector


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--port",
        default="/dev/ttyUSB0",
    )
    parser.add_argument("--baudrate", type=int, default=9600)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("action", choices=("status", "remote-on", "remote-off", "pump-on", "pump-off"))
    parser.add_argument(
        "--enable-actuation",
        action="store_true",
        help="Required for remote mode or pump commands; status remains read-only",
    )
    args = parser.parse_args()
    connector = ArduinoSerialStage1Connector(
        args.port,
        args.baudrate,
        args.timeout,
        enable_actuation=args.enable_actuation,
    )

    if args.action == "status":
        print(connector.read_state())
    elif args.action == "remote-on":
        connector.set_remote_control(True)
        print("Remote control enable command sent")
    elif args.action == "remote-off":
        connector.set_remote_control(False)
        print("Remote control disabled and pump-off command sent")
    elif args.action == "pump-on":
        connector.set_pump(True)
        print("Pump-on command sent")
    else:
        connector.set_pump(False)
        print("Pump-off command sent")


if __name__ == "__main__":
    main()
