import copy
import unittest
from src.pipeline import extract_features, generate_events
from src.v2 import make_dataset
from src.v4 import (baseline, record_review, verify_ledger, eligible_benign,
                    build_candidate, evaluate_candidate, detect, promote, rollback, demo)

class V4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.active,cls.calibration = baseline()
        cls.rows = extract_features(make_dataset(seed=101))

    def test_reproducible_comparison(self):
        a = demo(101)
        b = demo(101)
        self.assertEqual(a,b)
        self.assertEqual(set(a),{"rules","ml","hybrid"})

    def test_no_label_leakage(self):
        a = detect(self.rows,self.active)
        b = detect([{**r,"label":1-r["label"]} for r in self.rows],self.active)
        self.assertEqual([x["alert"] for x in a],[x["alert"] for x in b])

    def test_hash_chain_detects_tampering(self):
        ledger = record_review([],self.rows[0],"analyst-a","confirmed_benign","Verified maintenance")
        self.assertTrue(verify_ledger(ledger))
        altered = copy.deepcopy(ledger)
        altered[0]["decision"]="confirmed_threat"
        with self.assertRaises(ValueError):
            verify_ledger(altered)

    def test_two_independent_benign_reviews(self):
        row=self.rows[0]
        ledger=record_review([],row,"analyst-a","confirmed_benign","Verified")
        self.assertEqual(eligible_benign(ledger),[])
        with self.assertRaises(ValueError):
            record_review(ledger,row,"analyst-a","confirmed_benign","Duplicate")
        ledger=record_review(ledger,row,"analyst-b","confirmed_benign","Verified")
        self.assertEqual(len(eligible_benign(ledger)),1)

    def test_conflict_quarantines_window(self):
        row=self.rows[0]
        ledger=record_review([],row,"analyst-a","confirmed_benign","Looks normal")
        ledger=record_review(ledger,row,"analyst-b","confirmed_threat","Suspicious")
        self.assertEqual(eligible_benign(ledger),[])

    def test_candidate_requires_approval_and_reviews(self):
        with self.assertRaises(PermissionError):
            build_candidate([],self.active,self.calibration,approved_by="")
        with self.assertRaises(ValueError):
            build_candidate([],self.active,self.calibration,approved_by="analyst-a")

    def test_holdout_gate_report(self):
        result=evaluate_candidate(self.active,self.active,seeds=(201,202))
        self.assertTrue(result["passed"])
        self.assertEqual(result["active"],result["candidate"])

    def test_promotion_requires_independent_approver_and_gate(self):
        registry={"active":self.active,"previous":None,"version":1}
        candidate={"model":self.active,"evaluation":{"passed":True},"approved_by":"reviewer-a"}
        with self.assertRaises(PermissionError):
            promote(registry,candidate,"reviewer-a")
        with self.assertRaises(PermissionError):
            promote(registry,{**candidate,"evaluation":{"passed":False}},"reviewer-b")
        updated=promote(registry,candidate,"reviewer-b")
        self.assertEqual(updated["version"],2)
        reverted=rollback(updated,"reviewer-c")
        self.assertIs(reverted["active"],self.active)

    def test_nonfinite_features_rejected(self):
        invalid=[{**self.rows[0],"count":float("nan")}]
        with self.assertRaises(ValueError):
            detect(invalid,self.active)

if __name__=="__main__":
    unittest.main()
