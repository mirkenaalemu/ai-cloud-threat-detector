"""V4: synthetic-only human-reviewed adaptive model lifecycle.

No authentication, external persistence, live AWS input or autonomous deployment.
Designed for reproducible demonstration of controls, not production operation.
"""
import hashlib
import json
from datetime import datetime, timezone
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from src.pipeline import extract_features, generate_events, evaluate
from src.v2 import FEATURES, make_dataset

DECISIONS = {"confirmed_benign", "confirmed_threat", "uncertain"}
MODES = ("rules", "ml", "hybrid")

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False)

def fingerprint(row):
    """Stable fingerprint of features; excludes synthetic ground-truth labels."""
    return hashlib.sha256(_canonical({k: row[k] for k in ("principal", "window", *FEATURES)}).encode()).hexdigest()

def record_review(ledger, row, reviewer, decision, rationale, at=None):
    """Return an appended copy; reject duplicate reviewer votes and bad inputs.

    Caller-supplied reviewer identity is illustrative only; not authenticated.
    """
    if decision not in DECISIONS:
        raise ValueError("Unsupported review decision")
    if not reviewer or not reviewer.strip() or len(reviewer)>80:
        raise ValueError("Reviewer ID required")
    if not rationale or not rationale.strip() or len(rationale)>500:
        raise ValueError("Review rationale required (max 500 characters)")
    verify_ledger(ledger)
    item_id = fingerprint(row)
    if any(x["item_id"] == item_id and x["reviewer"] == reviewer for x in ledger):
        raise ValueError("One decision per reviewer per window")
    prior = ledger[-1]["hash"] if ledger else "GENESIS"
    item = {"item_id":item_id, "features":{k:float(row[k]) for k in FEATURES},
            "reviewer":reviewer, "decision":decision, "rationale":rationale.strip(),
            "at":at or datetime.now(timezone.utc).isoformat(), "previous_hash":prior}
    item["hash"] = hashlib.sha256(_canonical(item).encode()).hexdigest()
    return [*ledger, item]

def verify_ledger(ledger):
    previous = "GENESIS"
    for entry in ledger:
        data = {k:v for k,v in entry.items() if k!="hash"}
        expected = hashlib.sha256(_canonical(data).encode()).hexdigest()
        if entry["previous_hash"] != previous or entry["hash"] != expected:
            raise ValueError("Review history integrity check failed")
        previous = entry["hash"]
    return True

def eligible_benign(ledger, min_reviewers=2):
    """Require two distinct reviewers agreeing benign and zero threat/uncertain votes."""
    verify_ledger(ledger)
    grouped = {}
    for entry in ledger:
        grouped.setdefault(entry["item_id"], []).append(entry)
    accepted = []
    for entries in grouped.values():
        if any(e["decision"] != "confirmed_benign" for e in entries):
            continue
        if len({e["reviewer"] for e in entries}) >= min_reviewers:
            accepted.append(entries[0]["features"])
    return accepted

def _matrix(rows):
    x = np.array([[float(r[k]) for k in FEATURES] for r in rows], dtype=float)
    if x.ndim != 2 or x.shape[1] != len(FEATURES) or not np.isfinite(x).all():
        raise ValueError("Invalid or non-finite feature matrix")
    if (x < 0).any() or (x[:,1] > x[:,0]).any() or (x[:,2] > x[:,0]).any() or (x[:,3] > x[:,0]).any():
        raise ValueError("Inconsistent event features")
    return x

def fit_model(rows, calibration, seed=42, budget=0.02):
    """Train on approved benign rows; calibrate on separate trusted benign windows."""
    if len(rows)<30 or len(calibration)<30:
        raise ValueError("Need >=30 training and calibration windows")
    scaler = RobustScaler().fit(_matrix(rows))
    train = scaler.transform(_matrix(rows))
    cal = scaler.transform(_matrix(calibration))
    model = IsolationForest(n_estimators=120, contamination="auto", random_state=seed)
    model.fit(train)
    scores = model.decision_function(cal)
    if not np.isfinite(scores).all():
        raise ValueError("Non-finite model scores")
    return {"model":model, "scaler":scaler,
            "threshold":float(np.quantile(scores,budget)), "training_rows":len(rows)}

def score(rows, bundle):
    x = bundle["scaler"].transform(_matrix(rows))
    values = bundle["model"].decision_function(x)
    if not np.isfinite(values).all():
        raise ValueError("Non-finite detection scores")
    return values

def detect(rows, bundle, mode="hybrid"):
    if mode not in MODES:
        raise ValueError("Invalid detection mode")
    scores = score(rows,bundle)
    output = []
    for row,s in zip(rows,scores):
        rule = row["failed_logins"]>=3 or row["privileged_changes"]>=2 or row["count"]>=12
        ml = bool(s<bundle["threshold"])
        alert = rule if mode=="rules" else ml if mode=="ml" else rule or ml
        output.append({**row,"alert":bool(alert),"ml_anomaly":ml,
                       "anomaly_score":round(float(s),5),
                       "reasons":(["Rule threshold"] if rule else [])+
                                 (["ML anomaly"] if ml else [])})
    return output

def baseline():
    training = extract_features(generate_events(seed=11,benign=1200,malicious=0))
    calibration = extract_features(generate_events(seed=12,benign=1200,malicious=0))
    return fit_model(training,calibration),calibration

def evaluate_candidate(candidate, active, seeds=(201,202,203,204,205),
                       min_recall=0.70, max_fp_increase=0):
    """Gate on an independent fixed synthetic holdout, never on feedback rows."""
    current, proposed = [], []
    for seed in seeds:
        rows = extract_features(make_dataset(seed=seed))
        current.extend(detect(rows,active))
        proposed.extend(detect(rows,candidate))
    before, after = evaluate(current), evaluate(proposed)
    passed = (after["recall"] >= min_recall and
              after["recall"] >= before["recall"]-0.02 and
              after["fp"] <= before["fp"]+max_fp_increase and
              after["precision"] >= before["precision"]-0.02)
    return {"passed":bool(passed),"active":before,"candidate":after,
            "holdout_seeds":list(seeds),"reason":"All predefined synthetic holdout gates must pass"}

def build_candidate(ledger, active, calibration, approved_by, min_windows=30):
    """Human-triggered candidate only; no automatic promotion."""
    if not approved_by or not approved_by.strip():
        raise PermissionError("Explicit training approval required")
    clean = eligible_benign(ledger)
    if len(clean)<min_windows:
        raise ValueError(f"Need {min_windows} distinct doubly-reviewed benign windows")
    # Exclude extreme volumes as a basic poisoning guard; not a full defense.
    filtered = [r for r in clean if 0 < r["count"] <= 10 and
                r["failed_logins"] <= 2 and r["privileged_changes"] <= 1]
    if len(filtered)<min_windows:
        raise ValueError("Insufficient clean reviews after anomaly filtering")
    candidate = fit_model(filtered,calibration)
    gate = evaluate_candidate(candidate,active)
    return {"model":candidate,"evaluation":gate,"status":"candidate_only",
            "approved_by":approved_by,"reviewed_windows":len(filtered)}

def promote(registry, candidate, approver):
    """Explicit in-memory promotion; prior active model retained for rollback."""
    if not approver or not approver.strip():
        raise PermissionError("Explicit promotion approval required")
    if not candidate["evaluation"]["passed"]:
        raise PermissionError("Candidate failed holdout gate")
    if approver == candidate["approved_by"]:
        raise PermissionError("Independent promotion approver required")
    return {"active":candidate["model"],"previous":registry["active"],
            "version":registry["version"]+1,"status":"promoted"}

def rollback(registry, approver):
    if not approver or not approver.strip():
        raise PermissionError("Explicit rollback approval required")
    if registry.get("previous") is None:
        raise ValueError("No previous model")
    return {"active":registry["previous"],"previous":registry["active"],
            "version":registry["version"]+1,"status":"rolled_back"}

def demo(seed=101):
    active,_ = baseline()
    rows = extract_features(make_dataset(seed=seed))
    return {mode:evaluate(detect(rows,active,mode)) for mode in MODES}

if __name__=="__main__":
    print(json.dumps({"synthetic_seed":101,"modes":demo()},indent=2))
