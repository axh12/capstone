"""Calibrate a simulation-only process detector on normal Twin sessions.

No attack observations or evaluation results select the threshold. These
synthetic operating envelopes are experiment assumptions, not plant limits.
"""
import argparse
import json
import pickle
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent / 'Digital Twin'))
from physics_engine import PhysicsEngine, PhysicsParams
from detector_training import train_candidate
from research_state_profile import RESEARCH_PROCESS_FEATURES


def normal_sessions():
    rows = []
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    # Separate seeds and entire sessions for fitting, threshold calibration,
    # and normal-only diagnostics. Cover legitimate binary control changes.
    for session in range(60):
        rng = random.Random(4100 + session)
        twin = PhysicsEngine(PhysicsParams(random_seed=7100 + session))
        twin.state.lit101 = rng.uniform(450, 650)
        twin.state.lit301 = rng.uniform(650, 850)
        twin.state.ait202_ph = rng.uniform(7.1, 7.7)
        for tick in range(60):
            if tick % 10 == 0:
                twin.apply_actions({name: rng.randrange(2)
                                    for name in ('p101', 'mv101', 'mv201', 'p301')})
            state = twin.step()
            rows.append({**{name: state[name] for name in RESEARCH_PROCESS_FEATURES},
                         't_stamp': start + timedelta(seconds=session * 120 + tick),
                         'y_true': 0, 'session_id': f'normal-{session}',
                         'split': ('train' if session < 36 else
                                   'calibration' if session < 48 else 'test')})
    return pd.DataFrame(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=Path('validation/twin-calibrated'))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    data = normal_sessions()
    # Use the existing chronological normal-only training implementation.
    # The session boundaries coincide with its 60/20/20 timestamp split.
    models, report = train_candidate(data, RESEARCH_PROCESS_FEATURES,
                                     'swat-process', target_fpr=0.01)
    models['training_info']['calibration_domain'] = 'synthetic-swat-twin'
    models['training_info']['plant_topology'] = 'swat'
    report['calibration_domain'] = 'synthetic-swat-twin'
    report['limitations'] = [
        'Simulation-only calibration; not a replacement for historical SWaT evaluation.',
        'Normal operating ranges are declared simulation assumptions, not physical safety limits.',
        'No attack examples select the model or threshold.',
        'Process-only observations cannot identify malicious intent in a legitimate actuator state.',
        'Sustained process deviations may require multiple commands before detection.',
    ]
    data.to_csv(args.output_dir / 'normal-sessions.csv', index=False)
    with (args.output_dir / 'detector_candidate.pkl').open('wb') as handle:
        pickle.dump(models, handle)
    (args.output_dir / 'model-report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
