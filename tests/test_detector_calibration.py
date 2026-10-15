import json
import pickle
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import numpy as np
import pandas as pd
import sklearn

from detector_training import temporal_split, train_candidate
from realtime_anomaly_detector import RealTimeAnomalyDetector, SCORING_VERSION
from telemetry_to_dataset import convert


class CalibrationTests(unittest.TestCase):
    def detector(self):
        detector = RealTimeAnomalyDetector()
        detector.FEATURE_ORDER = ['x']
        detector.scaler = Mock()
        detector.scaler.transform.side_effect = lambda values: values
        detector.isolation_forest = Mock()
        detector.lof = Mock()
        detector.isolation_forest.decision_function.side_effect = lambda values: -values[:, 0]
        detector.lof.decision_function.side_effect = lambda values: -values[:, 0]
        detector.normal_mean = np.zeros(1)
        detector.normal_std = np.ones(1)
        detector.calibration = {name: np.array([0., 1., 2.]) for name in ('if','lof','z')}
        return detector

    def test_unseen_normal_support_is_not_diluted_by_ensemble(self):
        detector = self.detector()
        detector.normal_support = {'x': [0.0, 1.0]}
        detector.threshold = 0.95
        result = detector.predict({'x': 2.0})
        self.assertTrue(result.is_anomaly)
        self.assertEqual(result.attack_type, 'PROCESS_NOVELTY')
        self.assertEqual(result.feature_deviations['x']['normal_values'], [0.0, 1.0])
        np.testing.assert_array_equal(detector.score_samples([[1.0], [2.0]]),
                                      [detector.predict({'x': 1.0}).ensemble_score, 1.0])

    def test_ensemble_only_uses_same_model_without_actuator_override(self):
        detector = self.detector()
        detector.normal_support = {'x': [0.0, 1.0]}
        detector.threshold = 0.95
        with_support = detector.predict({'x': 2.0})
        detector.use_actuator_support = False
        ensemble_only = detector.predict({'x': 2.0})
        self.assertTrue(with_support.is_anomaly)
        self.assertFalse(ensemble_only.is_anomaly)
        self.assertEqual(ensemble_only.detection_basis, 'ensemble')
        self.assertEqual(ensemble_only.feature_deviations, {})
        self.assertEqual(ensemble_only.ensemble_score,
                         ensemble_only.ensemble_only_score)

    def test_continuous_tail_exceeds_old_plateau_without_actuator_gate(self):
        detector = self.detector()
        detector.tail_scales = {'if': 1.0, 'lof': 1.0, 'z': 1.0}
        scores = detector.score_samples([[3.0], [10.0], [100.0]], include_support=False)
        self.assertTrue(np.all(np.diff(scores) > 0))
        self.assertTrue(np.all(scores < 1.0))
        detector.threshold = float(scores[0])
        result = detector.predict({'x': 100.0})
        self.assertTrue(result.is_anomaly)
        self.assertEqual(result.detection_basis, 'ensemble')
        self.assertFalse(result.feature_deviations)
        self.assertEqual(detector.score_samples([[100.0]])[0], scores[-1])

    def test_lower_estimator_decisions_increase_anomaly_score(self):
        detector = self.detector()
        self.assertGreater(detector.predict({'x': 4}).ensemble_score,
                           detector.predict({'x': 0}).ensemble_score)

    def test_scoring_is_independent_of_other_batch_samples(self):
        detector = self.detector()
        self.assertEqual(detector.score_samples([[1]])[0], detector.score_samples([[1], [1000]])[0])

    def test_scalar_and_vectorized_scores_agree(self):
        detector = self.detector()
        expected = detector.score_samples([[0], [1], [3]])
        actual = [detector.predict({'x': value}).ensemble_score for value in (0,1,3)]
        np.testing.assert_array_equal(actual, expected)

    def test_missing_and_nonfinite_features_rejected(self):
        detector = self.detector()
        for features in ({}, {'x': float('nan')}, {'x': float('inf')}):
            with self.subTest(features=features), self.assertRaises(ValueError):
                detector.predict(features)

    def test_legacy_artifact_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'legacy.pkl'
            path.write_bytes(pickle.dumps({'feature_order': ['x']}))
            with self.assertRaisesRegex(ValueError, 'Legacy scoring'):
                RealTimeAnomalyDetector(str(path))
            self.assertIsNone(RealTimeAnomalyDetector(str(path), allow_legacy=True).calibration)

    def test_version_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'wrong.pkl'
            path.write_bytes(pickle.dumps({'scoring_version': SCORING_VERSION,
                'training_info': {'sklearn_version': 'wrong'}}))
            with self.assertRaisesRegex(ValueError, 'versions differ'):
                RealTimeAnomalyDetector(str(path))

    def data(self):
        rng = np.random.default_rng(42)
        return pd.DataFrame({'t_stamp': pd.date_range('2026-01-01', periods=200, freq='s'),
            'x': rng.normal(0, 1, 200), 'y_true': [0]*180 + [1]*20})

    def test_split_has_no_overlapping_timestamps(self):
        train, calibration, test = temporal_split(self.data())
        self.assertLess(train.t_stamp.max(), calibration.t_stamp.min())
        self.assertLess(calibration.t_stamp.max(), test.t_stamp.min())
        self.assertTrue((train.y_true == 0).all())
        self.assertTrue((calibration.y_true == 0).all())

    def test_test_labels_do_not_change_calibration_or_threshold(self):
        data = self.data()
        first, _ = train_candidate(data, ['x'], 'test')
        data.loc[data.index >= 160, 'y_true'] = 0
        second, _ = train_candidate(data, ['x'], 'test')
        self.assertEqual(first['threshold'], second['threshold'])
        for name in first['calibration']:
            np.testing.assert_array_equal(first['calibration'][name], second['calibration'][name])

    def test_score_references_use_training_not_calibration(self):
        models, _ = train_candidate(self.data(), ['x'], 'test')
        self.assertEqual(len(models['calibration']['if']), models['training_info']['samples'])

    def test_small_calibration_does_not_interpolate_an_unresolved_tail(self):
        models, report = train_candidate(self.data(), ['x'], 'test')
        self.assertFalse(report['target_fpr_supported'])
        self.assertEqual(report['calibration']['confusion_matrix']['fp'], 0)
        self.assertGreater(report['calibration_resolution'], 0.01)

    def test_model_roundtrip_and_recorded_feature_order(self):
        models, _ = train_candidate(self.data(), ['x'], 'test')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'candidate.pkl'
            path.write_bytes(pickle.dumps(models))
            detector = RealTimeAnomalyDetector(str(path))
            self.assertEqual(detector.FEATURE_ORDER, ['x'])
            self.assertEqual(detector.metadata['sklearn_version'], sklearn.__version__)
            self.assertTrue(np.isfinite(detector.predict({'x': 1}).ensemble_score))

    def test_dataset_conversion_requires_human_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'unlabeled.jsonl'
            path.write_text(json.dumps({'label': None, 'decision': 'BLOCK', 'model_features': {}})+'\n')
            with self.assertRaisesRegex(ValueError, 'human scenario label'):
                convert([path])
