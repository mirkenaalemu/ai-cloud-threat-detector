"""V5.1 model-selection transparency regression tests."""
import unittest
from src.v4 import baseline
from src.v5 import benchmark, select_configuration

class SelectionAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle, _ = baseline()

    def test_selection_audit_contains_all_modes(self):
        selection = select_configuration(self.bundle, selection_seeds=(151,))
        self.assertEqual(set(selection["validation_by_mode"]),
                         {"rules", "ml", "or", "contextual"})
        self.assertEqual(len(selection["candidate_results"]),
                         selection["candidate_count"])
        self.assertGreaterEqual(selection["eligible_candidate_count"], 1)

    def test_selected_candidate_is_eligible_and_uses_validation_f1(self):
        selection = select_configuration(self.bundle, selection_seeds=(152,))
        eligible = [c for c in selection["candidate_results"] if c["eligible"]]
        selected = [c for c in eligible
                    if c["mode"] == selection["selected_mode"]
                    and c["threshold"] == selection["threshold"]]
        self.assertTrue(selected)
        def ranking(c):
            m = c["metrics"]
            return (round(m["f1"], 12), round(m["recall"], 12), -m["fp"])
        self.assertEqual(ranking(selected[0]), max(map(ranking, eligible)))

    def test_duplicate_validation_seeds_rejected(self):
        with self.assertRaises(ValueError):
            select_configuration(self.bundle, selection_seeds=(151,151))

    def test_benchmark_keeps_holdout_separate(self):
        report = benchmark(selection_seeds=(151,), test_seeds=(301,))
        self.assertEqual(report["selection"]["selection_seeds"], [151])
        self.assertEqual(report["test_seeds"], [301])
        self.assertIn("selected", report["held_out"])

if __name__ == "__main__":
    unittest.main()
