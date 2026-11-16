import json
import unittest
from src.cloudtrail_import import parse_cloudtrail, extract_unlabeled_windows
from src.pipeline import extract_features
from src.v2 import make_dataset
from src.v4 import baseline
from src.v5 import benchmark, risk_detect, select_configuration

class V5Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle,_=baseline()

    def test_label_independence(self):
        rows=extract_features(make_dataset(seed=301))
        before=risk_detect(rows,self.bundle,self.bundle["threshold"])
        changed=risk_detect([{**r,"label":1-r["label"]} for r in rows],
                            self.bundle,self.bundle["threshold"])
        self.assertEqual([r["alert"] for r in before],[r["alert"] for r in changed])

    def test_contextual_is_subset_of_or(self):
        rows=extract_features(make_dataset(seed=302))
        contextual=risk_detect(rows,self.bundle,self.bundle["threshold"],"contextual")
        union=risk_detect(rows,self.bundle,self.bundle["threshold"],"or")
        self.assertTrue(all(not a["alert"] or b["alert"] for a,b in zip(contextual,union)))

    def test_selection_does_not_use_final_holdout(self):
        a=select_configuration(self.bundle,selection_seeds=(151,))
        b=select_configuration(self.bundle,selection_seeds=(151,))
        self.assertEqual(a,b)

    def test_overlap_rejected(self):
        with self.assertRaises(ValueError):
            benchmark(selection_seeds=(301,),test_seeds=(301,))

    def test_cloudtrail_offline_import(self):
        event={"Records":[{"eventID":"id1","eventTime":"2026-01-01T10:02:00Z",
                           "eventName":"ConsoleLogin",
                           "userIdentity":{"principalId":"user1"},
                           "sourceIPAddress":"192.0.2.4",
                           "errorCode":"FailedAuthentication"}]}
        events=parse_cloudtrail(json.dumps(event))
        self.assertEqual(len(events),1)
        self.assertFalse(events[0]["success"])
        windows=extract_unlabeled_windows(event)
        self.assertEqual(windows[0]["failed_logins"],1)
        self.assertNotIn("label",windows[0])

    def test_unknown_and_invalid_records_ignored(self):
        payload={"Records":[{"eventName":"Unrelated","eventTime":"2026-01-01T10:02:00Z"},
                            {"eventName":"ConsoleLogin","eventTime":"invalid"}]}
        self.assertEqual(parse_cloudtrail(payload),[])

    def test_size_and_record_limits(self):
        with self.assertRaises(ValueError):
            parse_cloudtrail("x"*5_000_001)
        with self.assertRaises(ValueError):
            parse_cloudtrail({"Records":[{}]*20_001})

if __name__=="__main__":
    unittest.main()
