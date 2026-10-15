"""Convert labeled gateway observations without mixing feature definitions."""
import argparse
import json
from pathlib import Path
import pandas as pd
from detector_training import NATIVE_FEATURES
from gateway_window_profile import GATEWAY_WINDOW_FEATURES, features_from_event


def convert(paths):
    rows = []
    for path in paths:
        for number, line in enumerate(Path(path).read_text().splitlines(), 1):
            event = json.loads(line)
            if event.get('label') not in (0, 1):
                raise ValueError(f"{path}:{number}: explicit human scenario label required")
            features = event['model_features']
            missing = set(NATIVE_FEATURES) - set(features)
            if missing:
                raise ValueError(f"{path}:{number}: missing {sorted(missing)}")
            rows.append({'t_stamp': event['timestamp'], 'y_true': event['label'],
                         **{key: features[key] for key in NATIVE_FEATURES}})
    if not rows:
        raise ValueError('No observations')
    return pd.DataFrame(rows).sort_values('t_stamp', kind='stable')


def convert_window_manifest(manifest_path):
    """Keep whole, explicitly labeled sessions in their declared partitions."""
    manifest_path = Path(manifest_path)
    sessions = json.loads(manifest_path.read_text()).get('sessions', [])
    if not sessions:
        raise ValueError('gateway-window manifest needs sessions')
    rows = []
    seen = set()
    for session in sessions:
        session_id = session.get('id')
        split = session.get('split')
        if not isinstance(session_id, str) or not session_id or session_id in seen:
            raise ValueError('Each session needs a unique nonempty id')
        if split not in ('train', 'calibration', 'test'):
            raise ValueError('Session split must be train, calibration or test')
        seen.add(session_id)
        path = manifest_path.parent / session['path']
        lines = path.read_text().splitlines()
        if not lines:
            raise ValueError(f'{path}: empty session')
        for number, line in enumerate(lines, 1):
            try:
                event = json.loads(line)
                if event.get('label') not in (0, 1):
                    raise ValueError('explicit human scenario label required')
                if split != 'test' and event['label'] != 0:
                    raise ValueError('train/calibration sessions must contain only normal observations')
                values = features_from_event(event)
                rows.append({'t_stamp': event['timestamp'], 'y_true': event['label'],
                             'session_id': session_id, 'split': split, **values})
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(f'{path}:{number}: {error}') from error
    return pd.DataFrame(rows).sort_values('t_stamp', kind='stable')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('logs', nargs='*')
    parser.add_argument('--output', required=True)
    parser.add_argument('--window-manifest', help='JSON sessions for 60-second gateway-window training')
    args = parser.parse_args()
    if bool(args.logs) == bool(args.window_manifest):
        parser.error('Provide either labeled native logs or --window-manifest')
    data = convert_window_manifest(args.window_manifest) if args.window_manifest else convert(args.logs)
    data.to_csv(args.output, index=False)
