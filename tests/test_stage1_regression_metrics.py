"""Guard the evaluation against hiding allowed attacks or miscounting replays."""
import unittest

from evaluate_stage1_regression import confusion


class Stage1RegressionMetricsTests(unittest.TestCase):
    def test_lead_in_misses_first_block_and_replay_are_all_counted(self):
        rows = [{'label': 0, 'decision': 'ALLOW'},
                {'label': 1, 'decision': 'ALLOW'},
                {'label': 1, 'decision': 'ALLOW'},
                {'label': 1, 'decision': 'BLOCK'},
                {'label': 1, 'decision': 'BLOCK'},
                {'label': 0, 'decision': 'ALLOW'}]
        result = confusion(rows)
        self.assertEqual(result['samples'], 6)
        self.assertEqual(result['confusion_matrix'], {'tn': 2, 'fp': 0, 'fn': 2, 'tp': 2})
        self.assertEqual(result['recall'], .5)

    def test_errors_are_not_counted_as_true_positives(self):
        with self.assertRaises(ValueError):
            confusion([{'label': 1, 'decision': 'ERROR'}])

    def test_false_alarms_are_preserved(self):
        self.assertEqual(confusion([{'label': 0, 'decision': 'BLOCK'}])['confusion_matrix'],
                         {'tn': 0, 'fp': 1, 'fn': 0, 'tp': 0})
