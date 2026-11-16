import unittest
from datetime import datetime
from src.pipeline import extract_features
from src.v5_2 import scenario_events, bootstrap_by_seed, benchmark, SCENARIOS

class V52Tests(unittest.TestCase):
    def test_scenarios_reproducible_and_valid(self):
        for scenario in SCENARIOS:
            a = scenario_events(401, scenario)
            self.assertEqual(a, scenario_events(401, scenario))
            self.assertTrue(all(datetime.fromisoformat(x["time"]) for x in a))
            self.assertEqual(sum(x["label"] for x in a),
                             sum(x["label"] for x in scenario_events(401, "standard")))

    def test_stress_scenarios_have_distinct_behavior(self):
        standard = extract_features(scenario_events(401, "standard"))
        admin = extract_features(scenario_events(401, "benign_admin_burst"))
        slow = extract_features(scenario_events(401, "low_and_slow"))
        shift = extract_features(scenario_events(401, "volume_shift"))
        self.assertGreater(len(admin), len(standard))
        self.assertGreater(len(shift), len(standard))
        self.assertGreater(len(slow), len(standard))

    def test_bootstrap_reproducible(self):
        records = [{"tp":3,"fp":1,"fn":2},{"tp":2,"fp":2,"fn":3}]
        self.assertEqual(bootstrap_by_seed(records, draws=30),
                         bootstrap_by_seed(records, draws=30))

    def test_reject_overlap(self):
        with self.assertRaises(ValueError):
            benchmark(seeds=(301, 401), scenarios=("standard",), bootstrap_draws=10)

    def test_benchmark_counts_and_selection(self):
        result = benchmark(seeds=(401,402), scenarios=("standard",), bootstrap_draws=20)
        self.assertIn(result["selected_mode"], ("rules","ml","or","contextual"))
        for mode in ("rules","selected"):
            row = result["scenarios"]["standard"][mode]
            self.assertEqual(row["tp"]+row["fp"]+row["fn"]+row["tn"],
                             sum(x["windows"] for x in row["per_seed"]))
            self.assertIn("f1", row["seed_cluster_bootstrap_95pct"])

if __name__ == "__main__":
    unittest.main()
