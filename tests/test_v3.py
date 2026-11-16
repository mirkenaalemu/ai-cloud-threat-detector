import unittest
from src.pipeline import extract_features, generate_events
from src.v2 import make_dataset
from src.v3 import fit_autoencoder, detect_v3, compare, drift_report, review_gated_retrain

class V3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = fit_autoencoder()
        cls.rows = extract_features(make_dataset(seed=101))

    def test_same_windows_across_modes(self):
        results = compare(seed=101, bundle=self.bundle)
        for m in ("rules", "neural", "hybrid"):
            self.assertEqual(sum(results[m][k] for k in ("tp","fp","fn","tn")), len(self.rows))

    def test_labels_do_not_affect_prediction(self):
        original = detect_v3(self.rows, self.bundle)
        flipped = detect_v3([{**r,"label":1-r["label"]} for r in self.rows], self.bundle)
        self.assertEqual([r["alert"] for r in original], [r["alert"] for r in flipped])

    def test_retraining_requires_approval(self):
        with self.assertRaises(PermissionError):
            review_gated_retrain([], self.bundle)
        with self.assertRaises(ValueError):
            review_gated_retrain([], self.bundle, approval=True)

    def test_drift_on_identical_rows(self):
        r = extract_features(generate_events(seed=51, benign=240, malicious=0))
        report = drift_report(r, r)
        self.assertEqual(report["max_standardized_shift"], 0)
        self.assertFalse(report["review_recommended"])

if __name__=="__main__":
    unittest.main()
