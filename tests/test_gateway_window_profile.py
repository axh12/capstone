"""The window model must train on the same observations the gateway emits."""

import json
import pickle
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from detector_training import temporal_split, train_candidate
from gateway_window_profile import GATEWAY_WINDOW_FEATURES, features_from_event
from realtime_anomaly_detector import RealTimeAnomalyDetector
from telemetry_to_dataset import convert_window_manifest


PROCESS = {'LIT101': 500.0, 'FIT101': 1.0, 'FIT201': 2.3,
           'LIT301': 800.0, 'FIT301': 1.8, 'AIT202_pH': 7.2}


def event(timestamp, label=0, count=2, window=60):
    statistics = {'packet_count': float(count), 'total_bytes': float(12 * count),
                  'packets_per_sec': count / 60, 'bytes_per_sec': count / 5,
                  'unique_src_ips': 1.0, 'unique_dst_ips': 1.0, 'unique_ip_pairs': 1.0,
                  'avg_packet_size': 12.0, 'max_packet_size': 12.0,
                  'packet_size_range': 0.0, 'bytes_per_packet': 12.0,
                  'small_packets_count': float(count)}
    return {'timestamp': timestamp.isoformat(), 'label': label,
            'network': {'src_ip': '192.0.2.1', 'dst_ip': '192.0.2.2',
                        'function_code': 6, 'register': 23, 'value': 1},
            'process': dict(PROCESS), 'network_statistics': statistics,
            'model_features': {**PROCESS, **statistics},
            'detection': {'window_seconds': window, 'window_packet_count': count}}


class GatewayWindowTests(unittest.TestCase):
    def test_paired_process_and_network_features(self):
        values = features_from_event(event(datetime.now(timezone.utc)))
        self.assertEqual(list(values), GATEWAY_WINDOW_FEATURES)
        self.assertEqual(values['packet_count'], 2)
        self.assertEqual(values['AIT202_pH'], 7.2)

    def test_rejects_old_or_inconsistent_windows(self):
        now = datetime.now(timezone.utc)
        for change in (
            lambda x: x['detection'].update(window_seconds=5),
            lambda x: x['network_statistics'].update(packets_per_sec=1.0),
            lambda x: x['network_statistics'].update(unique_src_ips=2.0),
            lambda x: x['process'].pop('AIT202_pH'),
            lambda x: x['model_features'].update(packet_count=999),
        ):
            with self.subTest(change=change):
                row = event(now)
                change(row)
                with self.assertRaises(ValueError):
                    features_from_event(row)

    def test_manifest_keeps_sessions_disjoint_and_labels_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            start = datetime(2026, 1, 1, tzinfo=timezone.utc)
            sessions = []
            for i, (split, label, size) in enumerate((
                ('train', 0, 40), ('calibration', 0, 15),
                ('test', 0, 10), ('test', 1, 10),
            )):
                path = root / f'session{i}.jsonl'
                samples = [event(start + timedelta(hours=i, seconds=j), label,
                                 count=1 + j % 4) for j in range(size)]
                path.write_text('\n'.join(json.dumps(sample) for sample in samples) + '\n')
                sessions.append({'id': f'session{i}', 'path': path.name, 'split': split})
            manifest = root / 'sessions.json'
            manifest.write_text(json.dumps({'sessions': sessions}))
            data = convert_window_manifest(manifest)
            train, calibration, test = temporal_split(data, 'declared_sessions')
            self.assertEqual((len(train), len(calibration), len(test)), (40, 15, 20))
            self.assertEqual(set(train.session_id) & set(test.session_id), set())
            models, report = train_candidate(data, GATEWAY_WINDOW_FEATURES,
                                             'gateway-window', 'declared_sessions')
            self.assertEqual(models['training_info']['window_seconds'], 60.0)
            self.assertEqual(report['split']['test_attack'], 10)
            artifact = root / 'candidate.pkl'
            artifact.write_bytes(pickle.dumps(models))
            loaded = RealTimeAnomalyDetector(str(artifact))
            self.assertEqual(loaded.FEATURE_ORDER, GATEWAY_WINDOW_FEATURES)
            self.assertEqual(loaded.feature_source, 'gateway-window')
            self.assertTrue(0 <= loaded.predict(data.iloc[0].to_dict()).ensemble_score <= 1)
            bad = data.copy()
            bad.loc[bad['split'] == 'train', 'y_true'] = 1
            with self.assertRaisesRegex(ValueError, 'normal'):
                temporal_split(bad, 'declared_sessions')
            mixed = data.copy()
            mixed.loc[mixed['session_id'] == 'session3', 'y_true'] = 0
            mixed.loc[mixed.index[-1], 'y_true'] = 1
            with self.assertRaisesRegex(ValueError, 'one human scenario label'):
                temporal_split(mixed, 'declared_sessions')


if __name__ == '__main__':
    unittest.main()
