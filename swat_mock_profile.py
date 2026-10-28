"""Calibrate a Stage-1-only mock using SWaT training-normal observations."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import sys

import pandas as pd

from detector_training import temporal_split
from research_state_profile import prepare_swat_stage1_only, STAGE1_ONLY_FEATURES

sys.path.insert(0, str(Path(__file__).resolve().parent / 'Digital Twin'))
from physics_engine import PhysicsParams


def fit_profile(data):
    train, _, _ = temporal_split(data)
    reference = prepare_swat_stage1_only(train)[STAGE1_ONLY_FEATURES].median().to_dict()
    stable = train.t_stamp.diff().dt.total_seconds().eq(1)
    for name in ('MV101.Status', 'P101.Status', 'P102.Status'):
        stable &= train[name].eq(train[name].shift())
    delta = train['LIT101.Pv'].diff()
    filling = (stable & train['MV101.Status'].eq(2)
               & train['P101.Status'].eq(1) & train['P102.Status'].eq(1)
               & delta.gt(0) & train['FIT101.Pv'].gt(0))
    draining = (stable & train['MV101.Status'].eq(1)
                & train['P101.Status'].eq(2) & train['P102.Status'].eq(1)
                & delta.lt(0))
    if filling.sum() < 10 or draining.sum() < 10:
        raise ValueError('Need at least ten stable Stage-1 filling and draining observations')
    inlet_values = train.loc[filling, 'FIT101.Pv']
    inlet = float(inlet_values.median())
    # Q[m3/h] / (3.6 * dh[mm/s]) = effective tank area[m2].
    area = float((inlet_values / (3.6 * delta[filling])).median())
    pump = float(-delta[draining].median() * 3.6 * area)
    noise = max(.001, float((inlet_values.quantile(.95) - inlet_values.quantile(.05)) / 2))
    return {
        'version': 2, 'domain': 'swat-stage1-only-mock',
        'training_rows': len(train), 'train_end': train.t_stamp.max().isoformat(),
        'normal_reference': reference,
        'normal_level_quantiles': {'low': float(train['LIT101.Pv'].quantile(.01)),
                                   'high': float(train['LIT101.Pv'].quantile(.99))},
        'calibration_counts': {'steady_filling': int(filling.sum()),
                               'steady_draining': int(draining.sum())},
        'physics': {'stage1_topology': 'swat_stage1',
                    'stage1_inlet_flow_m3h': inlet,
                    'stage1_pump_flow_m3h': pump,
                    'flow_noise_m3h': noise,
                    'tank_area_m2': {'lit101': area}},
        'limitations': [
            'Only LIT101, FIT101, MV101, P101 and P102 participate.',
            'Parameters use chronological training normals only, never calibration or test observations.',
            'Effective area and pump capacity are nominal mass-balance estimates, not physical measurements.',
            'P102 is assumed to have the same capacity as P101; standby duty needs independent validation.',
            'SWaT status 2 maps to binary 1, status 1 to binary 0; transitional status 0 is excluded from fitting.',
            'One accepted write advances one simulated second; reads do not advance time.',
            'No packet replay or full SWaT equivalence is claimed.',
        ],
    }


def load_profile(path, detector=None):
    profile = json.loads(Path(path).read_text())
    if profile.get('version') != 2 or profile.get('domain') != 'swat-stage1-only-mock':
        raise ValueError('Expected a Stage-1-only SWaT mock profile')
    values = profile['physics']
    expected = {'stage1_topology', 'stage1_inlet_flow_m3h', 'stage1_pump_flow_m3h',
                'flow_noise_m3h', 'tank_area_m2'}
    numbers = [values.get(k) for k in ('stage1_inlet_flow_m3h', 'stage1_pump_flow_m3h', 'flow_noise_m3h')]
    area = values.get('tank_area_m2', {})
    if (set(values) != expected or values['stage1_topology'] != 'swat_stage1'
            or set(area) != {'lit101'}
            or any(not isinstance(v, (int, float)) or not math.isfinite(v) or v <= 0
                   for v in [*numbers, area.get('lit101')])):
        raise ValueError('Invalid Stage-1-only mock physics')
    if detector is not None:
        if detector.feature_source != 'swat-stage1-only':
            raise ValueError('Stage-1 mock requires the swat-stage1-only detector')
        if detector.metadata.get('normal_reference') != profile['normal_reference']:
            raise ValueError('Mock and detector must share the training reference')
    return PhysicsParams(**values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, default=Path('Anomaly Detection/aligned_sensor_network_clean.csv'))
    parser.add_argument('--output', type=Path, default=Path('validation/swat-stage1/profile.json'))
    args = parser.parse_args()
    profile = fit_profile(pd.read_csv(args.data))
    profile['dataset_sha256'] = hashlib.sha256(args.data.read_bytes()).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(profile, indent=2) + '\n')
    print(json.dumps(profile, indent=2))


if __name__ == '__main__':
    main()
