"""Exercise overflow and sensor falsification through actual Stage-1 TCP paths."""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import struct

from evaluate_stage1_regression import confusion, render_matrix, serve
from mock_scada import MockScadaServer
from mock_stage1_telemetry import MockStage1TelemetrySource
from modbus_gateway import ModbusGateway, receive_frame
from orchestrator import IntegrationOrchestrator
from swat_mock_profile import load_profile


@contextmanager
def session(directory, model, profile, initial_level=None, spoof=None, stage1_guards=False):
    directory.mkdir()
    pipeline = IntegrationOrchestrator(detector_model_path=str(model),
        firewall_enabled=False, snort_blocking=True, snort_rules_path=str(directory / 'snort.rules'))
    pipeline.digital_twin.params = load_profile(profile, pipeline.anomaly_detector)
    with MockScadaServer(('127.0.0.1', 0)) as scada:
        st = serve(scada)
        try:
            with ModbusGateway(('127.0.0.1', 0), scada.server_address, pipeline,
                               telemetry_file=directory / 'telemetry.jsonl',
                               emergency_hook=scada.apply_emergency_actions,
                               stage1_guards=stage1_guards) as gateway:
                if initial_level is not None:
                    pipeline.digital_twin.state.lit101 = initial_level
                    pipeline.state_manager.transition(pipeline.digital_twin.snapshot())
                scada.initialize_plant(pipeline.digital_twin)
                if spoof is not None:
                    pipeline.stage1_connector = MockStage1TelemetrySource(scada, spoof)
                gt = serve(gateway)
                try:
                    yield pipeline, scada, gateway
                finally:
                    gateway.shutdown()
                    gt.join(timeout=2)
        finally:
            scada.shutdown()
            st.join(timeout=2)


def frame(tx, fc, register, value):
    return struct.pack('>HHHBBHH', tx, 0, 6, 1, fc, register, value)


def observe(pipeline, scada, gateway, request, scenario, label):
    count, history = len(scada.received), len(pipeline.decision_history)
    with socket.create_connection(gateway.server_address, timeout=5) as client:
        client.settimeout(5)
        client.sendall(request)
        reply = receive_frame(client)
    with gateway.transaction_lock:
        received = len(scada.received) == count + 1
        rule = pipeline.snort_rule_manager.rules_path
        row = dict(scenario=scenario, label=label, request=request.hex(), reply=reply.hex(),
                   forwarded=received, rule_generated=rule.exists(),
                   actual_mock_state=scada.plant.snapshot(),
                   actual_spill_m3=scada.plant.state.stage1_spill_m3)
        if len(pipeline.decision_history) == history:
            assert reply[7:] == b'\x86\x02' and not received
            row.update(decision='PROTOCOL_REJECTION', model_alarm=None)
            return row
        assert len(pipeline.decision_history) == history + 1
        event = pipeline.telemetry_events[-1]
        decision = pipeline.decision_history[-1]['decision']
        assert received == (decision == 'ALLOW')
        assert event.detection['forwarded'] == received
        row.update(decision=decision, model_alarm=event.detection['is_anomaly'],
                   score=event.detection['ensemble_score'], threshold=event.detection['threshold'],
                   detector_observation={k: event.model_features[k] for k in ('LIT101', 'FIT101')},
                   attribution=event.detection.get('rule_attribution'))
        if request[7] == 3:
            if decision == 'BLOCK':
                assert reply[7:] == b'\x83\x04', 'Blocked sensor read leaked a value'
                row.update(sensor_read_rejected=True, wire_value=None)
            else:
                assert reply[7:9] == b'\x03\x02'
                register = int.from_bytes(request[8:10], 'big')
                field, scale = ('LIT101', 10) if register == 100 else ('FIT101', 1000)
                value = int.from_bytes(reply[9:11], 'big')
                actual = round(row['actual_mock_state'][field] * scale)
                row.update(wire_sensor=field, wire_value=value / scale,
                           returned_sensor_matches_actual_mock=(value == actual))
        elif received:
            assert reply == request
        else:
            assert reply[7:] == b'\x86\x04'
        return row


def evaluate(output, model, profile, with_draining=False):
    output.mkdir(parents=True, exist_ok=False)
    rows, checks, scenarios = [], [], []
    # Labels and spoof values are declared before inference. No scoring threshold changes.
    plans = [
        ('benign_read', 0, 3, 100, 1, None, None, 1),
        ('benign_telemetry_source', 0, 3, 100, 1, None, {}, 1),
        ('benign_inlet_open', 0, 6, 30, 1, None, None, 1),
        ('overflow_from_normal', 1, 6, 30, 1, None, None, 12),
        ('overflow_near_capacity', 1, 6, 30, 1, 1198., None, 12),
        ('spoof_level_low', 1, 3, 100, 1, None, {'LIT101': 100.}, 1),
        ('spoof_level_high', 1, 3, 100, 1, None, {'LIT101': 1100.}, 1),
        ('spoof_flow_high', 1, 3, 110, 1, None, {'FIT101': 30.}, 1),
        ('spoof_level_subtle', 1, 3, 100, 1, None, {'LIT101': 700.}, 1),
        ('spoof_flow_subtle', 1, 3, 110, 1, None, {'FIT101': .05}, 1),
        ('spoof_level_persistent', 1, 3, 100, 1, None, {'LIT101': 100.}, 3),
    ]
    for name, label, fc, register, value, initial_level, spoof, steps in plans:
        with session(output / name, model, profile, initial_level, spoof) as (pipeline, scada, gateway):
            observed = []
            for step in range(1, steps + 1):
                request = frame(step, fc, register, value)
                row = observe(pipeline, scada, gateway, request, name, label)
                row['phase'] = 'initial_or_sustained'
                row['step'] = step
                rows.append(row)
                observed.append(row)
                if fc == 6 and row['decision'] == 'BLOCK':
                    replay = observe(pipeline, scada, gateway, request, name, label)
                    replay.update(phase='exact_replay', step=step)
                    assert replay['request'] == row['request']
                    assert replay['decision'] == 'BLOCK' and not replay['forwarded']
                    rows.append(replay)
                    observed.append(replay)
                    break
            if spoof is not None:
                # A sensor observation does not identify an attributable FC06 payload.
                assert not pipeline.snort_rule_manager.rules_path.exists()
                if spoof:
                    assert scada.plant.snapshot()['LIT101'] != spoof.get('LIT101', -1)
            scenarios.append(dict(name=name, label=label, spoof=spoof, initial_level=initial_level,
                                  decision_matrix=confusion(observed),
                                  model_alarms=sum(r['model_alarm'] for r in observed),
                                  generated_rule=any(r['rule_generated'] for r in observed),
                                  rejected_sensor_reads=sum(r.get('sensor_read_rejected', False) for r in observed),
                                  spill_m3=scada.plant.state.stage1_spill_m3,
                                  bad_sensor_responses=sum(r.get('returned_sensor_matches_actual_mock') is False for r in observed)))
    # These are rejected by register permissions, not detected by ML.
    with session(output / 'sensor_write_permissions', model, profile) as (pipeline, scada, gateway):
        for register in (1, 10, 100, 110):
            checks.append(observe(pipeline, scada, gateway, frame(register, 6, register, 999),
                                  'sensor_register_write', 1))
        assert not pipeline.decision_history
    report = dict(scenarios=scenarios, all_decisions=confusion(rows),
                  sensor_register_write_checks=checks, forwarding_checks_passed=len(rows),
                  scope=['LIT101', 'FIT101', 'MV101', 'P101', 'P102'],
                  limitations=[
                      'Local mock TCP, not Kali or physical SCADA; existing model and threshold unchanged.',
                      'Overflow oracle is independent simulated spilled volume at the declared 1200 mm capacity.',
                      'The near-capacity case deliberately begins in an already anomalous state.',
                      'Sensor falsification uses a lab connector at the existing telemetry boundary, not a remote Modbus sensor-write API.',
                      'Blocked reads return exception 04; model alarms, forwarding and returned-data integrity are reported separately.',
                      'Protocol-rejected sensor-register writes are excluded from the ML confusion matrix.',
                      'Generated Snort rules are not deployed to pfSense; repeat enforcement is gateway quarantine.',
                      'This threat set differs from earlier benchmarks and does not replace their results.',
                  ])
    if with_draining:
        from evaluate_stage1_regression import evaluate as evaluate_draining
        draining = evaluate_draining(output / 'draining-regression', model, profile, episodes=1)
        drain_rows = [json.loads(line) for line in
                      (output / 'draining-regression/results.jsonl').read_text().splitlines()]
        for row in rows:
            row['test_family'] = 'overflow_or_sensor'
        for row in drain_rows:
            row['test_family'] = 'draining_and_exact_replay'
        report['overflow_sensor_decisions'] = report['all_decisions']
        report['draining_regression'] = draining
        rows += drain_rows
        report['all_decisions'] = confusion(rows)
        report['forwarding_checks_passed'] = len(rows)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    (output / 'results.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    render_matrix(output / 'confusion-matrix.svg', 'Stage-1 expanded threat regression',
                  report['all_decisions'], 'Gateway decisions; sensor-wire integrity and actual spilled volume reported separately.')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--model', type=Path, default=Path('validation/swat-stage1/model/detector_candidate.pkl'))
    parser.add_argument('--profile', type=Path, default=Path('validation/swat-stage1/profile.json'))
    parser.add_argument('--with-draining', action='store_true', help='Also rerun draining, exact replay, and benign recovery; include every request')
    args = parser.parse_args()
    print(json.dumps(evaluate(args.output, args.model, args.profile, args.with_draining), indent=2))
