import unittest
from src.pipeline import extract_features
from src.v2 import make_dataset, train_detector, detect_v2, benchmark

class V2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model, cls.threshold = train_detector()

    def test_synthetic_attack_scenarios(self):
        rows = extract_features(make_dataset(seed=101))
        self.assertEqual(sum(r["label"] for r in rows), 32)

    def test_deterministic_data(self):
        self.assertEqual(make_dataset(seed=102), make_dataset(seed=102))

    def test_detector_does_not_use_labels(self):
        rows = extract_features(make_dataset(seed=103))
        a = detect_v2(rows, self.model, self.threshold)
        changed = [{**r, "label": 1-r["label"]} for r in rows]
        b = detect_v2(changed, self.model, self.threshold)
        self.assertEqual([r["alert"] for r in a], [r["alert"] for r in b])

    def test_benchmark_counts(self):
        report = benchmark(seeds=(101, 102), output=None)
        self.assertEqual(sum(report["totals"].values()), sum(r["windows"] for r in report["per_seed"]))
        self.assertEqual(report["totals"]["tp"] + report["totals"]["fn"], 64)

if __name__ == "__main__":
    unittest.main()
