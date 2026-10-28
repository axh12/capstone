"""Run labeled local Modbus scenarios and render observed decision confusion matrices."""
import argparse
from contextlib import redirect_stdout
import hashlib
import json
from pathlib import Path
import socket
import struct
import threading

from mock_scada import MockScadaServer
from modbus_gateway import ModbusGateway, receive_frame
from orchestrator import IntegrationOrchestrator
from run_mock_lab import LabGateway


def serve(server):
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={'poll_interval': 0.01}, daemon=True)
    thread.start()
    return thread


def evaluate(output, model=None, repeats=5, steps=8, swat_profile=None):
    if repeats < 1 or steps < 1:
        raise ValueError('repeats and steps must be positive')
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    # Intent is declared before inference. Each episode starts with a fresh Twin.
    # Dosing episodes include the lead-in commands: delayed detection counts as FN.
    scenarios = [('normal_read', 0, 3, 1, 1, steps),
                 ('normal_valve', 0, 6, 30, 1, steps),
                 ('attack_pump', 1, 6, 20, 1, steps),
                 ('attack_dosing', 1, 6, 23, 1, steps)]
    if model is None:
        scenarios = scenarios[:3]  # Fixture defines only pump-on as an attack.
    if swat_profile:
        if model is None:
            raise ValueError('Stage-1 mock evaluation requires a trained model')
        profile = json.loads(swat_profile.read_text())
        scenarios = [('normal_read', 0, 3, 1, 1, steps),
                     ('normal_fill', 0, 6, 30, 1, steps),
                     ('normal_transfer', 0, 6, 20, 1, steps),
                     ('normal_standby', 0, 6, 24, 1, steps),
                     ('attack_forced_fill', 1, 6, 30, 1, steps),
                     ('attack_forced_drain', 1, 6, 20, 1, steps)]
    telemetry = output / 'telemetry.jsonl'
    telemetry.write_text('')
    with (output / 'runtime.log').open('w') as log, redirect_stdout(log):
        for repeat in range(repeats):
            for name, label, function, address, value, count in scenarios:
                pipeline = IntegrationOrchestrator(
                    detector_model_path=str(model) if model else None,
                    firewall_enabled=False, snort_blocking=True,
                    snort_rules_path=str(output / f'{name}-{repeat}.rules'))
                if swat_profile:
                    from swat_mock_profile import load_profile
                    pipeline.digital_twin.params = load_profile(swat_profile, pipeline.anomaly_detector)
                with MockScadaServer(('127.0.0.1', 0)) as scada:
                    st = serve(scada)
                    try:
                        cls = ModbusGateway if model else LabGateway
                        with cls(('127.0.0.1', 0), scada.server_address, pipeline,
                                 telemetry_file=telemetry, label=label,
                                 emergency_hook=scada.apply_emergency_actions) as gateway:
                            if swat_profile:
                                if name.startswith('attack_'):
                                    # Predeclared stress episodes start near
                                    # training-normal boundaries, not test rows.
                                    boundary = 'high' if name == 'attack_forced_fill' else 'low'
                                    pipeline.digital_twin.state.lit101 = profile['normal_level_quantiles'][boundary]
                                    pipeline.state_manager.transition(pipeline.digital_twin.snapshot())
                                scada.initialize_plant(pipeline.digital_twin)
                            gt = serve(gateway)
                            try:
                                for index in range(count):
                                    request = struct.pack('>HHHBBHH', index + 1, 0, 6, 1,
                                                          function, address, value)
                                    before = len(scada.received)
                                    history = len(pipeline.decision_history)
                                    with socket.create_connection(gateway.server_address, timeout=5) as client:
                                        client.settimeout(5)
                                        client.sendall(request)
                                        reply = receive_frame(client)
                                    # Synchronize with telemetry persistence after the response is sent.
                                    with gateway.transaction_lock:
                                        if len(pipeline.decision_history) != history + 1:
                                            raise AssertionError('Missing classification')
                                        decision = pipeline.decision_history[-1]['decision']
                                        if decision not in ('ALLOW', 'BLOCK'):
                                            raise AssertionError(f'Unexpected decision: {decision}')
                                        forwarded = len(scada.received) == before + 1
                                        if forwarded != (decision == 'ALLOW'):
                                            raise AssertionError('SCADA receipt disagrees with gateway decision')
                                        if decision == 'ALLOW' and (reply[7] & 0x80):
                                            raise AssertionError('Unexpected forwarded response')
                                        rows.append(dict(scenario=name, repeat=repeat, step=index + 1,
                                                         label=label, prediction=int(decision == 'BLOCK'),
                                                         decision=decision, forwarded=forwarded,
                                                         request=request.hex(), reply=reply.hex(),
                                                         twin_state=pipeline.state_manager.snapshot(),
                                                         mock_state=scada.plant.snapshot() if scada.plant else None))
                            finally:
                                gateway.shutdown()
                                gt.join(timeout=2)
                    finally:
                        scada.shutdown()
                        st.join(timeout=2)
    cm = {key: 0 for key in ('tn', 'fp', 'fn', 'tp')}
    for row in rows:
        cm[{(0, 0): 'tn', (0, 1): 'fp', (1, 0): 'fn', (1, 1): 'tp'}[
            row['label'], row['prediction']]] += 1
    def ratio(n, d):
        return n / d if d else 0.0
    report = dict(mode='trained-model' if model else 'fixed-fixture',
                  model=str(model) if model else None,
                  model_sha256=hashlib.sha256(model.read_bytes()).hexdigest() if model else None,
                  samples=len(rows), repeats=repeats, steps_per_episode=steps,
                  swat_profile=str(swat_profile) if swat_profile else None,
                  confusion_matrix=cm,
                  accuracy=ratio(cm['tp'] + cm['tn'], len(rows)),
                  precision=ratio(cm['tp'], cm['tp'] + cm['fp']),
                  recall=ratio(cm['tp'], cm['tp'] + cm['fn']),
                  f1=ratio(2 * cm['tp'], 2 * cm['tp'] + cm['fp'] + cm['fn']),
                  false_positive_rate=ratio(cm['fp'], cm['fp'] + cm['tn']),
                  forwarding_checks_passed=len(rows),
                  limitations=['Synthetic local scenarios; not held-out dataset accuracy.',
                               'Repeated episodes are correlated, not independent samples.',
                               'Attack labels include lead-in commands before process effects become detectable.',
                               'No physical SCADA or pfSense deployment is exercised.'])
    report['scenarios'] = {}
    if swat_profile:
        report['scope'] = ['LIT101', 'FIT101', 'MV101', 'P101', 'P102']
        report['model_features'] = pipeline.anomaly_detector.FEATURE_ORDER
        report['limitations'].extend([
            'Stage-1 stress labels describe sustained forcing beyond the historical normal operating envelope, not confirmed real-plant attacks.',
            'Forced-fill and forced-drain episodes start at the training-normal 99th and 1st level percentiles respectively.',
            'This Stage-1 benchmark differs from the earlier multi-stage dosing benchmark; accuracies are not directly comparable.',
        ])
    for name, *_ in scenarios:
        observed = [row for row in rows if row['scenario'] == name]
        report['scenarios'][name] = {
            'samples': len(observed),
            'blocked': sum(row['prediction'] for row in observed),
            'forwarded': sum(row['forwarded'] for row in observed),
            'first_blocked_step_by_repeat': [
                next((row['step'] for row in observed
                      if row['repeat'] == repeat and row['prediction']), None)
                for repeat in range(repeats)],
        }
    (output / 'results.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    cells = [('TN', cm['tn'], 180, 130), ('FP', cm['fp'], 360, 130),
             ('FN', cm['fn'], 180, 260), ('TP', cm['tp'], 360, 260)]
    svg = ['<svg xmlns="http://www.w3.org/2000/svg" width="620" height="470" viewBox="0 0 620 470">',
           '<rect width="620" height="470" fill="white"/>',
           '<g font-family="sans-serif" text-anchor="middle" fill="#172536">',
           f'<text x="310" y="30" font-size="22">Mock SCADA: {report["mode"]}</text>',
           '<text x="270" y="75">Predicted normal</text><text x="450" y="75">Predicted attack</text>',
           '<text x="82" y="195">Actual normal</text><text x="82" y="325">Actual attack</text>']
    for key, value, x, y in cells:
        color = '#bfdfd5' if key in ('TN', 'TP') else '#f5cdc3'
        svg.extend([f'<rect x="{x}" y="{y}" width="175" height="125" fill="{color}"/>',
                    f'<text x="{x+87}" y="{y+50}" font-size="18">{key}</text>',
                    f'<text x="{x+87}" y="{y+90}" font-size="32">{value}</text>'])
    svg.extend([f'<text x="310" y="420">n={len(rows)} | Precision {report["precision"]:.1%} | Recall {report["recall"]:.1%}</text>',
                '<text x="310" y="450" font-size="13">Synthetic local scenarios; not real-world detection accuracy</text></g></svg>'])
    (output / 'confusion-matrix.svg').write_text('\n'.join(svg))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=Path('validation/mock-scada'))
    parser.add_argument('--model', type=Path)
    parser.add_argument('--swat-profile', type=Path)
    parser.add_argument('--repeats', type=int, default=5)
    parser.add_argument('--steps', type=int, default=8,
                        help='Requests per episode; report longer runs separately from the eight-step baseline')
    args = parser.parse_args()
    if args.repeats < 1 or args.steps < 1:
        parser.error('--repeats and --steps must be positive')
    if args.swat_profile and not args.model:
        parser.error('--swat-profile requires --model')
    print(json.dumps(evaluate(args.output_dir, args.model, args.repeats, args.steps,
                              args.swat_profile), indent=2))
