"""Guard test-level counting and the predeclared expanded-case inventory."""
import unittest

from evaluate_l1_suite import outcome_matrix, plans, low_level_prevention


class L1SuiteReportingTests(unittest.TestCase):
    def test_manifest_ids_are_unique_and_each_case_has_criteria(self):
        cases=plans()
        self.assertEqual(len({c['id'] for c in cases}),len(cases))
        self.assertTrue(all(c['criterion'] for c in cases))
        for kind in ('normal','changeover','hazard','drift','frozen','fault','protocol',
                     'traffic','rule','recovery','restart','restart_rule','expiry','downstream','export_failure'):
            self.assertIn(kind,{c['kind'] for c in cases})

    def test_matrix_counts_named_tests_not_request_totals(self):
        cases=[dict(category='benign',passed=True,status='PASS',requests=100),
               dict(category='benign',passed=False,status='FAIL',requests=1),
               dict(category='malicious',passed=True,status='PASS',requests=300),
               dict(category='malicious',passed=False,status='FAIL',requests=20)]
        self.assertEqual(outcome_matrix(cases)['confusion_matrix'],dict(tn=1,fp=1,fn=1,tp=1))
        self.assertEqual(outcome_matrix(cases)['tests'],4)

    def test_robustness_and_execution_errors_are_not_ml_true_positives(self):
        cases=[dict(category='robustness',passed=True,status='PASS'),
               dict(category='malicious',passed=False,status='ERROR')]
        self.assertEqual(outcome_matrix(cases)['tests'],0)

    def test_low_level_interlock_is_graded_on_new_depletion_not_initial_fault(self):
        self.assertTrue(low_level_prevention(99.,99.))
        self.assertFalse(low_level_prevention(99.,98.9))
        self.assertTrue(low_level_prevention(101.,100.))
        self.assertFalse(low_level_prevention(101.,99.9))
