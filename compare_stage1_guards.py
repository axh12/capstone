"""Replay the identical labeled baseline traces with optional Stage-1 guards.

No early stopping: later baseline attack packets remain in the denominator
even if the new policy blocks earlier. Labels, bytes, order, initial state,
model and threshold are unchanged. The new policy is hybrid, not retrained ML.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket

from evaluate_stage1_regression import confusion, render_matrix
from evaluate_stage1_threats import session
from modbus_gateway import receive_frame


def compare(baseline, output, model, profile):
    original = [json.loads(s) for s in (baseline / 'results.jsonl').read_text().splitlines()]
    metadata = json.loads((baseline / 'report.json').read_text())
    assert metadata['draining_regression']['model_sha256'] == hashlib.sha256(model.read_bytes()).hexdigest(), 'Baseline model differs'
    plans = {s['name']: s for s in metadata['scenarios']}
    output.mkdir(parents=True, exist_ok=False)
    groups = {}
    for row in original:
        key = (row.get('test_family'), row.get('scenario'), row.get('episode'))
        groups.setdefault(key, []).append(row)
    observed, summaries = [], []
    for number, ((family, name, episode), trace) in enumerate(groups.items(), 1):
        plan = plans.get(name, {})
        directory = output / f'trace-{number}'
        with session(directory, model, profile, plan.get('initial_level'),
                     plan.get('spoof'), stage1_guards=True) as (pipeline, scada, gateway):
            group_rows = []
            for old in trace:
                request = bytes.fromhex(old['request'])
                before, history = len(scada.received), len(pipeline.decision_history)
                with socket.create_connection(gateway.server_address, timeout=5) as client:
                    client.settimeout(5)
                    client.sendall(request)
                    reply = receive_frame(client)
                with gateway.transaction_lock:
                    assert len(pipeline.decision_history) == history + 1
                    event = pipeline.telemetry_events[-1]
                    assert event.detection['threshold'] == old['threshold'], 'Baseline threshold differs'
                    decision = pipeline.decision_history[-1]['decision']
                    forwarded = len(scada.received) == before + 1
                    assert forwarded == (decision == 'ALLOW')
                    assert event.detection['forwarded'] == forwarded
                    if decision == 'BLOCK':
                        assert reply[7:] == bytes([request[7] | 0x80, 4])
                    elif request[7] == 6:
                        assert reply == request
                    row = dict(test_family=family, scenario=name, episode=episode,
                               phase=old.get('phase'), step=old.get('step'),
                               label=old['label'], request=old['request'], reply=reply.hex(),
                               baseline_decision=old['decision'], decision=decision, forwarded=forwarded,
                               detection=event.detection, model_features=event.model_features,
                               actual_mock_state=scada.plant.snapshot(),
                               actual_spill_m3=scada.plant.state.stage1_spill_m3,
                               rule_generated=pipeline.snort_rule_manager.rules_path.exists())
                    observed.append(row)
                    group_rows.append(row)
            summaries.append(dict(scenario=name or f'draining-episode-{episode}',
                before=confusion(trace), after=confusion(group_rows),
                first_malicious_block_step=next((r['step'] for r in group_rows
                    if r['label'] == 1 and r['decision'] == 'BLOCK'), None),
                final_spill_m3=scada.plant.state.stage1_spill_m3,
                rule_generated=pipeline.snort_rule_manager.rules_path.exists()))
    assert len(observed) == len(original)
    assert [(r['label'],r['request']) for r in observed] == [(r['label'],r['request']) for r in original]
    report = dict(samples=len(observed), baseline=str(baseline),
        baseline_rows_sha256=hashlib.sha256((baseline / 'results.jsonl').read_bytes()).hexdigest(),
        model=str(model), model_sha256=hashlib.sha256(model.read_bytes()).hexdigest(),
        before=confusion(original), after=confusion(observed), scenarios=summaries,
        policy={'forecast_seconds':60, 'level_residual_tolerance_mm':5,
                'flow_residual_tolerance_m3h':.1, 'capacity_limit_mm':1200},
        checks={'identical_labels_bytes_order_and_count':True,
                'all_mock_receipts_match_decisions':True,
                'model_and_threshold_unchanged':True},
        limitations=[
            'Hybrid predictive/physics/residual policy, not an ML-only accuracy improvement.',
            'Policy was developed after inspecting these failures; this is a development regression, not untouched validation.',
            'The 60-second horizon, 5 mm and 0.1 m3/h tolerances are explicit lab settings requiring independent calibration.',
            'Normal inlet-open and malicious inlet-open have identical initial observations; intent alone cannot distinguish them.',
            'Every baseline malicious lead-in remains in the matrix; later early-blocked requests are still replayed.',
            'Small within-tolerance and slow-drift sensor attacks remain possible.',
            'Forecast assumes the command persists and simplified Twin dynamics are accurate.',
            'Isolated local TCP; Snort rules generated but not deployed to pfSense.',
        ])
    (output / 'results.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in observed))
    (output / 'report.json').write_text(json.dumps(report,indent=2)+'\n')
    render_matrix(output / 'confusion-matrix.svg', 'Stage-1 guarded pipeline: same 313 requests',
                  report['after'], 'Hybrid guard development regression; identical baseline labels and packet bytes.')
    return report


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',type=Path,default=Path('validation/stage1-expanded-threats-20261028'))
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--model',type=Path,default=Path('validation/swat-stage1/model/detector_candidate.pkl'))
    parser.add_argument('--profile',type=Path,default=Path('validation/swat-stage1/profile.json'))
    args=parser.parse_args()
    print(json.dumps(compare(args.baseline,args.output,args.model,args.profile),indent=2))
