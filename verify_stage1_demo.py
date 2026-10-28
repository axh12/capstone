"""Exercise the Kali demo client against isolated, real loopback TCP servers."""
import argparse
import json
import subprocess
import sys
import threading
from pathlib import Path

from mock_scada import MockScadaServer
from modbus_gateway import ModbusGateway
from orchestrator import IntegrationOrchestrator
from swat_mock_profile import load_profile


def serve(server):
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={'poll_interval': .01}, daemon=True)
    thread.start()
    return thread


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('validation/stage1-demo-proof'))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    telemetry = args.output / 'telemetry.jsonl'
    telemetry.write_text('')
    pipeline = IntegrationOrchestrator(
        detector_model_path='validation/swat-stage1/model/detector_candidate.pkl',
        firewall_enabled=False, snort_blocking=True,
        snort_rules_path=str(args.output / 'snort.rules'))
    pipeline.digital_twin.params = load_profile('validation/swat-stage1/profile.json',
                                               pipeline.anomaly_detector)
    report = {'mode': 'actual-trained-model', 'network': 'local-loopback; not Kali VM evidence'}
    with MockScadaServer(('127.0.0.1', 0)) as scada:
        st = serve(scada)
        try:
            with ModbusGateway(('127.0.0.1', 0), scada.server_address, pipeline,
                               telemetry_file=telemetry,
                               emergency_hook=scada.apply_emergency_actions) as gateway:
                scada.initialize_plant(pipeline.digital_twin)
                gt = serve(gateway)
                try:
                    for case in ('normal', 'attack', 'repeat', 'recovery'):
                        received = len(scada.received)
                        first_event = len(pipeline.telemetry_events)
                        result = subprocess.run([
                            sys.executable, 'stage1_demo.py', '--host', '127.0.0.1',
                            '--port', str(gateway.server_address[1]), '--case', case,
                            '--interval', '0'], capture_output=True, text=True, timeout=120)
                        (args.output / f'{case}-client.txt').write_text(result.stdout + result.stderr)
                        if result.returncode:
                            raise AssertionError(f'{case} client failed: {result.stdout} {result.stderr}')
                        with gateway.transaction_lock:
                            rows = [json.loads(s) for s in telemetry.read_text().splitlines()][first_event:]
                            assert rows, f'No telemetry for {case}'
                            assert all('transaction_id' in row['network'] for row in rows)
                            assert all(row['forwarded'] == (row['decision'] == 'ALLOW') for row in rows)
                            receipt_delta = len(scada.received) - received
                            assert receipt_delta == sum(row['forwarded'] for row in rows)
                            expected = 'ALLOW' if case in ('normal', 'recovery') else 'BLOCK'
                            assert rows[-1]['decision'] == expected, f'{case}: {rows[-1]["decision"]}'
                            if case in ('attack', 'repeat'):
                                assert not rows[-1]['forwarded']
                                assert scada.registers[20] == 0
                            if case == 'normal':
                                assert scada.registers[20] == 0
                            report[case] = {
                                'requests': len(rows), 'forwarded': receipt_delta,
                                'last_transaction': rows[-1]['network']['transaction_id'],
                                'last_decision': rows[-1]['decision'],
                                'last_forwarded': rows[-1]['forwarded'],
                                'reason': rows[-1]['detection'].get('rule_attribution'),
                                'mock_p101': scada.registers[20],
                                'mock_state': scada.plant.snapshot(),
                            }
                    assert '06 00 14 00 01' in (args.output / 'snort.rules').read_text()
                    assert report['normal']['last_transaction'] == report['recovery']['last_transaction']
                    assert report['attack']['last_transaction'] == report['repeat']['last_transaction']
                    report['command_rule_verified'] = True
                finally:
                    gateway.shutdown()
                    gt.join(timeout=2)
        finally:
            scada.shutdown()
            st.join(timeout=2)
    (args.output / 'proof.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
