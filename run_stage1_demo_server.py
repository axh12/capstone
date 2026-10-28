"""Start a fresh Stage-1 presentation session on the Ubuntu VM."""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import socket
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--listen-host', required=True, help='Ubuntu IP reachable from your Kali VM')
    parser.add_argument('--stage1-guards', action='store_true', help='Enable predictive safety and sensor-residual guards')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    os.chdir(root)
    for path in ('validation/swat-stage1/model/detector_candidate.pkl',
                 'validation/swat-stage1/profile.json'):
        if not Path(path).exists():
            parser.error(f'Missing {path}. Follow the model preparation commands in docs/kali-stage1-demo.md.')
    for host, port in ((args.listen_host, 5020), ('127.0.0.1', 15020)):
        try:
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((host, port))
        except OSError as error:
            parser.error(f'Cannot bind {host}:{port}: {error}. Use the Ubuntu IP and stop the previous lab launcher first.')
    name = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + f'-{os.getpid()}'
    output = Path('validation/stage1-demo-sessions') / name
    output.mkdir(parents=True)
    telemetry = output / 'telemetry.jsonl'
    telemetry.touch()
    print('\nSTAGE 1 PRESENTATION SESSION — actual trained model', flush=True)
    print('Scope: LIT101 / FIT101 / MV101 / P101 / P102', flush=True)
    print(f'SESSION DIRECTORY: {output}', flush=True)
    print('Ubuntu terminal 2 — copy this exact command:', flush=True)
    print(f'  python3 watch_stage1_demo.py --telemetry {telemetry} --from-start', flush=True)
    print('Kali terminal — copy stage1_demo.py to Kali, then run:', flush=True)
    print(f'  python3 stage1_demo.py --host {args.listen_host} --case walkthrough', flush=True)
    print(f'Rules for screenshot 4: {output / "snort.rules"}', flush=True)
    print('Fresh session; pfSense deployment disabled. Ctrl+C stops this launcher.\n', flush=True)
    command = [sys.executable, '-u', 'run_mock_lab.py',
        '--listen-host', args.listen_host, '--plant-topology', 'swat_stage1',
        '--model', 'validation/swat-stage1/model/detector_candidate.pkl',
        '--swat-profile', 'validation/swat-stage1/profile.json',
        '--rules-file', str(output / 'snort.rules'), '--telemetry-file', str(telemetry)]
    if args.stage1_guards:
        command.append('--stage1-guards')
    os.execv(sys.executable, command)


if __name__ == '__main__':
    main()
