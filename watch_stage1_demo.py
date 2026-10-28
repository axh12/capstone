"""Print compact, transaction-correlated evidence from gateway telemetry."""
import argparse
import json
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--telemetry', type=Path, required=True)
    parser.add_argument('--from-start', action='store_true')
    parser.add_argument('--once', action='store_true', help='Print existing evidence and exit; useful for exporting a rehearsal log')
    args = parser.parse_args()
    print('STAGE 1 GATEWAY EVIDENCE | LIT101, FIT101, MV101, P101, P102', flush=True)
    print('Client exception 04 is confirmed as BLOCKED only when decision=BLOCK below.', flush=True)
    print(f'Watching {args.telemetry}', flush=True)
    allowed = 0
    try:
        if args.once and not args.telemetry.exists():
            parser.error('Telemetry file does not exist')
        while not args.telemetry.exists():
            time.sleep(.1)
        with args.telemetry.open() as handle:
            if not args.from_start and not args.once:
                handle.seek(0, 2)
            pending = ''
            while True:
                chunk = handle.readline()
                if not chunk:
                    if args.once:
                        break
                    time.sleep(.1)
                    continue
                pending += chunk
                if not pending.endswith('\n'):
                    continue
                row = json.loads(pending)
                pending = ''
                network, detection = row['network'], row['detection']
                tx = network.get('transaction_id')
                if tx is None:
                    print('Missing transaction ID: restart gateway with the updated code.', flush=True)
                    continue
                decision = row['decision']
                if decision == 'ALLOW':
                    allowed += 1
                # Keep the terminal legible during the sustained episode.
                if decision == 'ALLOW' and 2000 < tx <= 3000 and (tx - 2000) % 50:
                    continue
                forwarded = row.get('forwarded')
                flag = 'YES' if forwarded is True else 'NO' if forwarded is False else 'UNKNOWN'
                score, threshold = detection.get('ensemble_score'), detection.get('threshold')
                print(f"tx={tx} | {decision} | forwarded={flag} | LIT101={row['process'].get('LIT101')} mm | score={score} | threshold={threshold}", flush=True)
                if decision == 'BLOCK':
                    print(f"  Reason: {detection.get('rule_attribution')} | Twin commit: {detection.get('twin_commit')}", flush=True)
                    print(f"  Mock safety action: {detection.get('mock_safety_actions')} | allowed records seen={allowed}", flush=True)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
