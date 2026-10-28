"""Stage-1 regression: benign, sustained malicious forcing, exact replay, benign.

The main matrix includes EVERY malicious lead-in request. Replay blocks are
true positives of gateway enforcement, not new independent ML detections.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct
import threading

from mock_scada import MockScadaServer
from modbus_gateway import ModbusGateway, receive_frame
from orchestrator import IntegrationOrchestrator
from swat_mock_profile import load_profile


def confusion(rows):
    cells = dict(tn=0, fp=0, fn=0, tp=0)
    for row in rows:
        if row['label'] not in (0, 1) or row['decision'] not in ('ALLOW', 'BLOCK'):
            raise ValueError('Invalid label or decision; errors cannot be counted as successful blocks')
        key = {(0, False): 'tn', (0, True): 'fp',
               (1, False): 'fn', (1, True): 'tp'}[row['label'], row['decision'] == 'BLOCK']
        cells[key] += 1
    def ratio(a, b):
        return a / b if b else 0.
    tn, fp, fn, tp = (cells[key] for key in ('tn', 'fp', 'fn', 'tp'))
    return {'samples': len(rows), 'confusion_matrix': cells,
            'accuracy': ratio(tn + tp, len(rows)), 'precision': ratio(tp, tp + fp),
            'recall': ratio(tp, tp + fn), 'f1': ratio(2 * tp, 2 * tp + fp + fn),
            'false_positive_rate': ratio(fp, fp + tn)}


def serve(server):
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={'poll_interval': .01}, daemon=True)
    thread.start()
    return thread


def frame(transaction, value):
    return struct.pack('>HHHBBHH', transaction, 0, 6, 1, 6, 20, value)


def render_matrix(path, title, result, note):
    cm = result['confusion_matrix']
    svg = ['<svg xmlns="http://www.w3.org/2000/svg" width="820" height="590" viewBox="0 0 820 590">',
           '<rect width="820" height="590" fill="#f8fafc"/>',
           '<g font-family="sans-serif" fill="#172536" text-anchor="middle">',
           f'<text x="410" y="35" font-size="23" font-weight="bold">{title}</text>',
           '<text x="410" y="66" font-size="14">Stage 1 · actual trained model · real loopback Modbus TCP</text>',
           '<text x="340" y="112">Predicted normal / ALLOW</text>',
           '<text x="590" y="112">Predicted malicious / BLOCK</text>',
           '<text x="100" y="227">Actual benign</text>',
           '<text x="100" y="387">Actual malicious</text>']
    for key, x, y in [('tn', 220, 140), ('fp', 470, 140), ('fn', 220, 300), ('tp', 470, 300)]:
        color = '#c6e8dc' if key in ('tn', 'tp') else '#f7cec6'
        svg += [f'<rect x="{x}" y="{y}" width="235" height="145" rx="8" fill="{color}"/>',
                f'<text x="{x+117}" y="{y+43}" font-size="20">{key.upper()}</text>',
                f'<text x="{x+117}" y="{y+105}" font-size="43">{cm[key]}</text>']
    svg += [f'<text x="410" y="485">n={result["samples"]} · Precision {result["precision"]:.2%} · Recall {result["recall"]:.2%}</text>',
            f'<text x="410" y="515">Accuracy {result["accuracy"]:.2%} · F1 {result["f1"]:.2%}</text>',
            f'<text x="410" y="550" font-size="13">{note}</text>',
            '<text x="410" y="575" font-size="13">Snort rule generated; replay enforced by gateway quarantine; no pfSense deployment.</text>',
            '</g></svg>']
    path.write_text('\n'.join(svg))


def evaluate(output, model, profile, episodes=3, max_requests=400):
    if episodes < 1 or not 1 <= max_requests <= 1000:
        raise ValueError('Use positive episodes and 1..1000 malicious requests per episode')
    output.mkdir(parents=True, exist_ok=False)
    rows, episode_reports = [], []
    for episode in range(episodes):
        directory = output / f'episode-{episode + 1}'
        directory.mkdir()
        rules = directory / 'snort.rules'
        telemetry = directory / 'telemetry.jsonl'
        pipeline = IntegrationOrchestrator(detector_model_path=str(model),
            firewall_enabled=False, snort_blocking=True, snort_rules_path=str(rules))
        pipeline.digital_twin.params = load_profile(profile, pipeline.anomaly_detector)
        with MockScadaServer(('127.0.0.1', 0)) as scada:
            st = serve(scada)
            try:
                with ModbusGateway(('127.0.0.1', 0), scada.server_address, pipeline,
                                   telemetry_file=telemetry,
                                   emergency_hook=scada.apply_emergency_actions) as gateway:
                    scada.initialize_plant(pipeline.digital_twin)
                    gt = serve(gateway)
                    try:
                        def exchange(request, phase, label, step):
                            before, history = len(scada.received), len(pipeline.decision_history)
                            with socket.create_connection(gateway.server_address, timeout=5) as client:
                                client.settimeout(5)
                                client.sendall(request)
                                reply = receive_frame(client)
                            with gateway.transaction_lock:
                                assert len(pipeline.decision_history) == history + 1
                                decision = pipeline.decision_history[-1]['decision']
                                assert decision in ('ALLOW', 'BLOCK')
                                received = len(scada.received) == before + 1
                                assert received == (decision == 'ALLOW'), 'Mock receipt contradicts decision'
                                assert reply == (request if received else request[:4] + b'\x00\x03\x01\x86\x04')
                                event = pipeline.telemetry_events[-1]
                                assert event.detection['forwarded'] == received
                                row = dict(episode=episode + 1, phase=phase, label=label,
                                           step=step, decision=decision, forwarded=received,
                                           transaction_id=int.from_bytes(request[:2], 'big'),
                                           request=request.hex(), reply=reply.hex(),
                                           score=event.detection['ensemble_score'],
                                           threshold=event.detection['threshold'],
                                           attribution=event.detection.get('rule_attribution'),
                                           rule_exists=rules.exists(),
                                           mock_state=scada.plant.snapshot())
                                rows.append(row)
                                return row

                        benign = frame(1000, 0)
                        first = exchange(benign, 'benign_before', 0, 1)
                        assert first['decision'] == 'ALLOW' and not rules.exists()
                        rejected, blocked = None, None
                        for step in range(1, max_requests + 1):
                            request = frame(2000 + step, 1)
                            observed = exchange(request, 'malicious_forcing', 1, step)
                            if observed['decision'] == 'BLOCK':
                                rejected, blocked = request, observed
                                break
                        if rejected is None:
                            raise AssertionError('No attributed block within request cap; no replay success can be claimed')
                        rule_text = rules.read_text()
                        assert 'drop tcp' in rule_text and '06 00 14 00 01' in rule_text
                        assert 'register 20 value 0' not in rule_text
                        rule_hash = hashlib.sha256(rules.read_bytes()).hexdigest()
                        replay = exchange(rejected, 'malicious_exact_replay', 1, 1)
                        assert replay['request'] == blocked['request'], 'Replay must be byte-identical'
                        assert replay['decision'] == 'BLOCK' and not replay['forwarded']
                        assert replay['attribution'] == 'previously quarantined command; existing rule'
                        assert hashlib.sha256(rules.read_bytes()).hexdigest() == rule_hash
                        after = exchange(benign, 'benign_after', 0, 1)
                        assert after['request'] == first['request'], 'Final benign packet must be identical'
                        assert after['decision'] == 'ALLOW' and after['forwarded']
                        assert scada.registers[20] == scada.registers[24] == scada.registers[30] == 0
                        stored = [json.loads(line) for line in telemetry.read_text().splitlines()]
                        assert len(stored) == len([r for r in rows if r['episode'] == episode + 1])
                        episode_reports.append(dict(episode=episode + 1,
                            first_blocked_malicious_request=blocked['step'],
                            rule_path=str(rules), rule_sha256=rule_hash,
                            byte_identical_replay_blocked=True,
                            byte_identical_benign_after_allowed=True))
                    finally:
                        gateway.shutdown()
                        gt.join(timeout=2)
            finally:
                scada.shutdown()
                st.join(timeout=2)
    report = {'scope': ['LIT101', 'FIT101', 'MV101', 'P101', 'P102'],
              'model': str(model), 'model_sha256': hashlib.sha256(model.read_bytes()).hexdigest(),
              'profile': str(profile), 'episodes': episode_reports,
              'all_transactions': confusion(rows),
              'phases': {phase: confusion([r for r in rows if r['phase'] == phase]) for phase in
                         ('benign_before', 'malicious_forcing', 'malicious_exact_replay', 'benign_after')},
              'post_attribution_enforcement': confusion([r for r in rows if r['phase'] in
                                                        ('malicious_exact_replay', 'benign_after')]),
              'forwarding_checks_passed': len(rows),
              'limitations': [
                  'Synthetic local TCP scenarios; not a live Kali or physical-plant test.',
                  'Every malicious lead-in is retained as a false negative when allowed.',
                  'Replay blocks are true positives of learned gateway enforcement, not independent ML detections.',
                  'Snort drop rules are generated and verified; the replay is stopped by gateway quarantine, not a running Snort/pfSense engine.',
                  'Post-attribution matrix is conditional enforcement validation, not overall detector accuracy.',
                  'Episodes use the same initial operating point and are correlated.',
                  'This longer scenario differs from the previous 80-request boundary-start benchmark; its results remain valid.',
              ]}
    (output / 'results.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    render_matrix(output / 'confusion-matrix.svg', 'End-to-end regression: ALL requests',
                  report['all_transactions'], 'Includes every allowed malicious lead-in request as FN.')
    render_matrix(output / 'post-attribution-confusion-matrix.svg', 'Post-attribution enforcement checks',
                  report['post_attribution_enforcement'], 'Exact malicious replay + benign afterward only; conditional on an already learned command.')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='Fresh output directory; existing evidence is never overwritten')
    parser.add_argument('--model', type=Path, default=Path('validation/swat-stage1/model/detector_candidate.pkl'))
    parser.add_argument('--profile', type=Path, default=Path('validation/swat-stage1/profile.json'))
    parser.add_argument('--episodes', type=int, default=3)
    parser.add_argument('--max-requests', type=int, default=400)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.output, args.model, args.profile, args.episodes, args.max_requests), indent=2))
