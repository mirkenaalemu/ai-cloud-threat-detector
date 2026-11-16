import unittest
from src.pipeline import generate_events,extract_features,detect,evaluate

class PipelineTests(unittest.TestCase):
    def test_reproducible_events(self):
        self.assertEqual(generate_events(),generate_events())
    def test_no_missing_event_ids(self):
        e=generate_events()
        self.assertEqual(len(e),len({x['event_id'] for x in e}))
    def test_feature_windows(self):
        rows=extract_features(generate_events())
        self.assertTrue(all(r['count']>0 for r in rows))
        self.assertEqual(sum(r['count'] for r in rows),276)
    def test_alerts_and_metrics(self):
        result=detect(extract_features(generate_events()))
        self.assertTrue(any(r['alert'] for r in result))
        m=evaluate(result)
        self.assertEqual(m['tp']+m['fp']+m['fn']+m['tn'],len(result))
    def test_seed_reproducibility(self):
        r=extract_features(generate_events())
        self.assertEqual(detect(r),detect(r))

if __name__=='__main__': unittest.main()
