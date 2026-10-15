import unittest

import numpy as np
import pandas as pd

from detector_training import temporal_split, train_candidate
from research_state_profile import (
    RESEARCH_STATE_FEATURES,
    RESEARCH_PROCESS_FEATURES,
    SWAT_AGGREGATE_FEATURES,
    SWAT_ALIGNED_FEATURES,
    initialize_twin_from_training_reference,
    prepare_swat_stage1,
    prepare_swat_process,
    prepare_swat_aligned,
)
from orchestrator import PhysicsEngine


class ResearchStateProfileTests(unittest.TestCase):
    def data(self):
        size = 200
        return pd.DataFrame({
            't_stamp': pd.date_range('2026-01-01', periods=size, freq='s'),
            'y_true': [0] * 180 + [1] * 20,
            'LIT101.Pv': 700 + np.arange(size) * .2,
            'FIT101.Pv': np.arange(size) % 2,
            'FIT201.Pv': 2.3 + (np.arange(size) % 3) * .01,
            'LIT301.Pv': 850 + np.arange(size) * .1,
            'FIT301.Pv': 1.8 + (np.arange(size) % 4) * .01,
            'AIT202.Pv': 8.1 + (np.arange(size) % 3) * .01,
        })

    def test_mapping_uses_exact_historical_sensor_columns(self):
        frame = prepare_swat_stage1(self.data())
        self.assertEqual(list(frame), ['t_stamp', 'y_true', *RESEARCH_STATE_FEATURES])
        self.assertEqual(frame.loc[0, 'LIT101'], 700)
        with self.assertRaisesRegex(ValueError, 'Missing SWaT Stage 1'):
            prepare_swat_stage1(self.data().drop(columns=['FIT301.Pv']))

    def test_operating_point_uses_only_training_normal_rows(self):
        frame = prepare_swat_stage1(self.data())
        train, _, _ = temporal_split(frame)
        models, _ = train_candidate(frame, RESEARCH_STATE_FEATURES, 'swat-stage1')
        expected = train[RESEARCH_STATE_FEATURES].median().to_dict()
        self.assertEqual(models['training_info']['normal_reference'], expected)
        self.assertEqual(models['normal_support'], {})

    def test_process_profile_maps_ph_and_initializes_twin(self):
        frame = prepare_swat_process(self.data())
        self.assertEqual(list(frame), ['t_stamp', 'y_true', *RESEARCH_PROCESS_FEATURES])
        self.assertEqual(frame.loc[0, 'AIT202_pH'], 8.1)
        reference = {name: float(frame.loc[0, name]) for name in RESEARCH_PROCESS_FEATURES}
        twin = PhysicsEngine()
        initialize_twin_from_training_reference(twin, reference)
        self.assertEqual(twin.snapshot()['AIT202_pH'], 8.1)
        with self.assertRaisesRegex(ValueError, 'Missing SWaT pH'):
            prepare_swat_process(self.data().drop(columns=['AIT202.Pv']))

    def test_aligned_profile_keeps_network_and_sensor_values_on_same_row(self):
        data = self.data()
        for feature in SWAT_AGGREGATE_FEATURES:
            data[feature] = np.arange(len(data), dtype=float)
        prepared = prepare_swat_aligned(data)
        self.assertEqual(list(prepared), ['t_stamp', 'y_true', *SWAT_ALIGNED_FEATURES])
        self.assertEqual(prepared.loc[10, 'LIT101'], data.loc[10, 'LIT101.Pv'])
        self.assertEqual(prepared.loc[10, 'packet_count'], data.loc[10, 'packet_count'])
        with self.assertRaisesRegex(ValueError, 'Missing aligned SWaT network'):
            prepare_swat_aligned(data.drop(columns=['packet_count']))

    def test_twin_initialization_is_physically_consistent(self):
        twin = PhysicsEngine()
        reference = {'LIT101': 740, 'FIT101': 0, 'FIT201': 2.3,
                     'LIT301': 929, 'FIT301': 1.8}
        initialize_twin_from_training_reference(twin, reference)
        self.assertEqual(twin.snapshot()['LIT101'], 740)
        self.assertEqual(twin.snapshot()['LIT301'], 929)
        self.assertEqual(twin.state.mv101, 0)
        self.assertEqual(twin.state.mv201, 1)
        self.assertEqual(twin.state.p101, 1)
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            initialize_twin_from_training_reference(twin, {'LIT101': 740})
