import unittest
from src.pipeline import extract_features
from src.v5_2 import scenario_events
from src.v5_3 import temporal_features, detect_temporal, benchmark
from src.v4 import baseline
from src.v5 import select_configuration

class V53Tests(unittest.TestCase):
    def test_causal_history_excludes_future_and_other_principals(self):
        rows = [
            {"principal":"a","window":"2026-01-01T10:00:00+00:00",
             "count":1,"failed_logins":1,"privileged_changes":0,"distinct_ips":1,"label":1},
            {"principal":"b","window":"2026-01-01T10:10:00+00:00",
             "count":1,"failed_logins":10,"privileged_changes":0,"distinct_ips":1,"label":0},
            {"principal":"a","window":"2026-01-01T10:20:00+00:00",
             "count":1,"failed_logins":1,"privileged_changes":0,"distinct_ips":1,"label":1},
        ]
        out = temporal_features(rows)
        self.assertEqual(out[0]["history_failed_logins"], 1)
        self.assertEqual(out[2]["history_failed_logins"], 2)
        self.assertEqual(out[2]["history_distinct_windows"], 2)
        self.assertEqual(out[1]["history_failed_logins"], 10)

    def test_old_windows_expire(self):
        rows = [
            {"principal":"a","window":f"2026-01-{day:02d}T10:00:00+00:00",
             "count":1,"failed_logins":1,"privileged_changes":0,"distinct_ips":1,"label":0}
            for day in (1,3)]
        self.assertEqual(temporal_features(rows)[1]["history_failed_logins"],1)

    def test_temporal_detection_preserves_baseline_alerts(self):
        bundle, _ = baseline()
        choice = select_configuration(bundle)
        rows = extract_features(scenario_events(601, "low_and_slow"))
        from src.v5 import risk_detect
        baseline_rows = risk_detect(rows, bundle, choice["threshold"], choice["selected_mode"])
        improved = detect_temporal(rows, bundle, choice["threshold"], choice["selected_mode"], 3)
        self.assertTrue(all(not old["alert"] or new["alert"]
                            for old,new in zip(baseline_rows,improved)))
        self.assertTrue(any(x["temporal_escalation"] for x in improved))

    def test_disjoint_seed_guard(self):
        with self.assertRaises(ValueError):
            benchmark(validation_seeds=(401,502), test_seeds=(601,602),bootstrap_draws=10)
        with self.assertRaises(ValueError):
            benchmark(validation_seeds=(501,502), test_seeds=(501,602),bootstrap_draws=10)

    def test_small_holdout_reproducible(self):
        args = {"validation_seeds":(501,502),"test_seeds":(601,602),"bootstrap_draws":10}
        a = benchmark(**args)
        b = benchmark(**args)
        self.assertEqual(a,b)
        self.assertEqual(set(a["results"]),{"standard","benign_admin_burst","low_and_slow","volume_shift"})

if __name__=="__main__":
    unittest.main()
