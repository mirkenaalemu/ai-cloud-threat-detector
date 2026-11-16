"""Synthetic V2 detector. Research-only: not validated on real cloud logs."""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
import numpy as np
from sklearn.ensemble import IsolationForest
from src.pipeline import generate_events, extract_features, evaluate

FEATURES = ("count", "failed_logins", "privileged_changes", "distinct_ips")

def make_dataset(seed=100, benign=800, attacks_per_type=8):
    """Benign traffic, three simple attack types, maintenance, and stealth events."""
    events = generate_events(seed=seed, benign=benign, malicious=0)
    rng = random.Random(seed + 8000)
    base = datetime(2026, 1, 6, tzinfo=timezone.utc)
    for scenario_index, scenario in enumerate(("login_burst", "privilege_burst", "mixed_sequence")):
        for n in range(attacks_per_type):
            principal = f"attack-{scenario}-{n:03d}"
            timestamp = base + timedelta(minutes=20 * (n + attacks_per_type * scenario_index))
            for k in range(8):
                action = "ConsoleLogin" if scenario == "login_burst" else "AttachUserPolicy"
                success = scenario != "login_burst"
                if scenario == "mixed_sequence":
                    action = "ConsoleLogin" if k < 4 else "AttachUserPolicy"
                    success = k >= 4
                events.append({
                    "event_id": f"a-{seed}-{scenario}-{n}-{k}",
                    "time": (timestamp + timedelta(seconds=k)).isoformat(),
                    "principal": principal,
                    "source_ip": f"198.51.100.{rng.randrange(1, 15)}",
                    "action": action, "success": success, "label": 1
                })
    for n in range(8):
        for k in range(4):
            events.append({
                "event_id": f"benign-maint-{seed}-{n}-{k}",
                "time": (base + timedelta(days=2, minutes=n*20, seconds=k)).isoformat(),
                "principal": f"maintenance-{n}", "source_ip": "10.0.1.10",
                "action": "AttachUserPolicy" if n % 2 else "ConsoleLogin",
                "success": bool(n % 2), "label": 0
            })
    for n in range(8):
        events.append({
            "event_id": f"stealth-{seed}-{n}",
            "time": (base + timedelta(days=3, minutes=n*20)).isoformat(),
            "principal": f"stealth-{n}", "source_ip": "198.51.100.45",
            "action": "AttachUserPolicy", "success": True, "label": 1
        })
    return events

def train_detector(train_seed=11, calibration_seed=12, false_alert_budget=0.02):
    """Train and calibrate on separately seeded benign synthetic windows."""
    if not 0 < false_alert_budget < 0.5:
        raise ValueError("false_alert_budget must be between 0 and 0.5")
    train = extract_features(generate_events(seed=train_seed, benign=1200, malicious=0))
    calibration = extract_features(generate_events(seed=calibration_seed, benign=1200, malicious=0))
    xtrain = np.array([[r[c] for c in FEATURES] for r in train], dtype=float)
    xcal = np.array([[r[c] for c in FEATURES] for r in calibration], dtype=float)
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    model.fit(xtrain)
    threshold = float(np.quantile(model.decision_function(xcal), false_alert_budget))
    return model, threshold

def detect_v2(rows, model, threshold):
    """Rules generate alerts; Isolation Forest scores are informational only."""
    x = np.array([[r[c] for c in FEATURES] for r in rows], dtype=float)
    scores = model.decision_function(x)
    out = []
    for row, score in zip(rows, scores):
        evidence = []
        if row["failed_logins"] >= 3:
            evidence.append("3+ failed logins in 10 minutes")
        if row["privileged_changes"] >= 2:
            evidence.append("2+ privileged changes in 10 minutes")
        if row["count"] >= 12:
            evidence.append("12+ events in 10 minutes")
        anomaly = bool(score < threshold)
        out.append({
            **row, "anomaly_score": round(float(score), 5),
            "ml_anomaly": anomaly, "alert": bool(evidence),
            "reasons": evidence + (["ML anomaly (informational)"] if anomaly else [])
        })
    return out

def benchmark(seeds=(101, 102, 103, 104, 105), output="results/v2_metrics.json"):
    model, threshold = train_detector()
    per_seed = []
    for seed in seeds:
        rows = extract_features(make_dataset(seed=seed))
        detections = detect_v2(rows, model, threshold)
        per_seed.append({"seed": seed, "windows": len(rows), **evaluate(detections)})
    totals = {k: sum(r[k] for r in per_seed) for k in ("tp", "fp", "fn", "tn")}
    p = totals["tp"] / (totals["tp"] + totals["fp"]) if totals["tp"] + totals["fp"] else 0
    r = totals["tp"] / (totals["tp"] + totals["fn"]) if totals["tp"] + totals["fn"] else 0
    summary = {
        "method": "separate synthetic train/calibration/evaluation seeds",
        "training_seed": 11, "calibration_seed": 12,
        "evaluation_seeds": list(seeds), "threshold": round(threshold, 6),
        "totals": totals, "precision": round(p, 4), "recall": round(r, 4),
        "f1": round(2*p*r/(p+r), 4) if p+r else 0,
        "per_seed": per_seed,
        "limitations": "Synthetic scenarios deliberately match alert rules. No real-world validation."
    }
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(summary, indent=2))
    return summary

if __name__ == "__main__":
    print(json.dumps(benchmark(), indent=2))
