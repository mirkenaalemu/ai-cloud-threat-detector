"""Synthetic cloud security anomaly detection proof of concept."""
import csv
import json
import random
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

ACTIONS = ['ListBuckets', 'GetObject', 'DescribeInstances', 'ConsoleLogin', 'AttachUserPolicy']


def generate_events(seed=42, benign=240, malicious=36):
    rng = random.Random(seed)
    start = datetime(2026, 1, 5, 9, tzinfo=timezone.utc)
    events = []
    for i in range(benign):
        user = f'user-{rng.randrange(12):02d}'
        action = rng.choices(ACTIONS, weights=[35, 30, 25, 9, 1])[0]
        events.append({'event_id': f'e{i:04}', 'time': (start + timedelta(minutes=i)).isoformat(),
                       'principal': user, 'source_ip': f'10.0.0.{rng.randrange(1,40)}',
                       'action': action, 'success': True, 'label': 0})
    for j in range(malicious):
        i = benign + j
        events.append({'event_id': f'e{i:04}', 'time': (start + timedelta(minutes=benign+j//6)).isoformat(),
                       'principal': 'suspicious-actor', 'source_ip': f'198.51.100.{1+j%3}',
                       'action': 'AttachUserPolicy' if j%3 == 0 else 'ConsoleLogin',
                       'success': False if j%3 else True, 'label': 1})
    return events


def extract_features(events):
    """Context features in 10-minute windows; synthetic labels excluded from training."""
    groups = defaultdict(list)
    for e in events:
        dt = datetime.fromisoformat(e['time'])
        key = (e['principal'], dt.replace(minute=(dt.minute//10)*10, second=0, microsecond=0))
        groups[key].append(e)
    rows = []
    for (principal, window), group in sorted(groups.items(), key=lambda x:(x[0][1],x[0][0])):
        rows.append({'principal':principal, 'window':window.isoformat(),
                     'count':len(group), 'failed_logins':sum(e['action']=='ConsoleLogin' and not e['success'] for e in group),
                     'privileged_changes':sum(e['action']=='AttachUserPolicy' for e in group),
                     'distinct_ips':len({e['source_ip'] for e in group}),
                     'label':int(any(e['label'] for e in group)),
                     'event_ids':[e['event_id'] for e in group]})
    return rows


def detect(rows, seed=42):
    cols = ['count','failed_logins','privileged_changes','distinct_ips']
    X = np.array([[r[c] for c in cols] for r in rows], dtype=float)
    # A small synthetic benign baseline. Do not train on labeled attack windows.
    baseline = np.array([x for x,r in zip(X,rows) if r['label']==0])
    if len(baseline)<10: raise ValueError('Need at least ten benign training windows')
    model = IsolationForest(n_estimators=100, contamination=0.08, random_state=seed)
    model.fit(baseline)
    scores = model.decision_function(X)
    preds = model.predict(X)
    out=[]
    for r, score, pred in zip(rows,scores,preds):
        reasons=[]
        if r['failed_logins']>=3: reasons.append('multiple failed logins')
        if r['privileged_changes']>=2: reasons.append('repeated privileged changes')
        if r['count']>=12: reasons.append('high event volume')
        if pred==-1: reasons.append('ML anomaly')
        out.append({**r,'anomaly_score':round(float(score),5),'alert':bool(reasons),'reasons':reasons})
    return out


def evaluate(rows):
    tp=sum(r['alert'] and r['label']==1 for r in rows)
    fp=sum(r['alert'] and r['label']==0 for r in rows)
    fn=sum(not r['alert'] and r['label']==1 for r in rows)
    tn=sum(not r['alert'] and r['label']==0 for r in rows)
    precision=tp/(tp+fp) if tp+fp else 0
    recall=tp/(tp+fn) if tp+fn else 0
    return {'tp':tp,'fp':fp,'fn':fn,'tn':tn,'precision':round(precision,3),
            'recall':round(recall,3),'f1':round(2*precision*recall/(precision+recall),3) if precision+recall else 0}


def run(output='results'):
    out=Path(output);out.mkdir(parents=True,exist_ok=True)
    events=generate_events(); rows=detect(extract_features(events)); metrics=evaluate(rows)
    (out/'events.json').write_text(json.dumps(events,indent=2))
    (out/'detections.json').write_text(json.dumps(rows,indent=2))
    (out/'metrics.json').write_text(json.dumps(metrics,indent=2))
    return metrics

if __name__=='__main__':
    print(json.dumps(run(),indent=2))
