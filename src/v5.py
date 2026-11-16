"""V5: reproducible calibration experiments on separate synthetic datasets.

The selection set is separate from the final evaluation seeds. No test labels
are used by the deployed scoring function. These are research experiments.
"""
from src.pipeline import extract_features, evaluate
from src.v2 import make_dataset
from src.v4 import baseline, score

def risk_detect(rows, bundle, threshold, mode="contextual"):
    """Rules plus gated ML escalation; scores computed without labels."""
    if mode not in ("rules", "ml", "or", "contextual"):
        raise ValueError("Unknown mode")
    values = score(rows, bundle)
    result = []
    for row, s in zip(rows, values):
        rules = (row["failed_logins"] >= 3 or row["privileged_changes"] >= 2
                 or row["count"] >= 12)
        ml = bool(s < threshold)
        # A single privileged change or failed login is weak corroborating context.
        context = row["privileged_changes"] >= 1 or row["failed_logins"] >= 1
        alert = {"rules": rules, "ml": ml, "or": rules or ml,
                 "contextual": rules or (ml and context)}[mode]
        result.append({**row, "alert": bool(alert),
                       "anomaly_score": float(s),
                       "reasons": (["Rule threshold"] if rules else []) +
                                  (["Calibrated anomaly with context"] if ml and context else [])})
    return result

def aggregate(bundle, seeds, threshold, mode):
    detected = []
    for seed in seeds:
        rows = extract_features(make_dataset(seed=seed))
        detected.extend(risk_detect(rows, bundle, threshold, mode))
    return evaluate(detected)

def select_configuration(bundle, selection_seeds=(151,152,153,154,155),
                         minimum_recall=0.75):
    """Choose a detector using validation data only; report the decision.

    Final held-out test seeds are never accessed here. Prefer highest
    validation F1, then recall, then fewer false positives. Rules remain
    eligible; there is no forced preference for the contextual model.
    """
    if not selection_seeds:
        raise ValueError("Selection seeds required")
    if len(set(selection_seeds)) != len(selection_seeds):
        raise ValueError("Selection seeds must be unique")
    reference = aggregate(bundle, selection_seeds, bundle["threshold"], "rules")
    # Generate thresholds using validation anomaly-score distributions.
    # Labels are used only for choosing the validation winner.
    import numpy as np
    validation_rows = []
    for seed in selection_seeds:
        validation_rows.extend(extract_features(make_dataset(seed=seed)))
    validation_scores = np.asarray(score(validation_rows, bundle), dtype=float)
    if not np.isfinite(validation_scores).all():
        raise ValueError("Non-finite validation anomaly scores")
    quantiles = (0.005, 0.01, 0.02, 0.04, 0.08, 0.12, 0.20, 0.30)
    thresholds = sorted(set([float(bundle["threshold"])] +
                            [float(np.quantile(validation_scores, q)) for q in quantiles]))
    candidates = [{"mode": "rules", "threshold": float(bundle["threshold"]),
                   "metrics": reference, "eligible": True}]
    required_recall = max(minimum_recall, reference["recall"])
    for threshold in thresholds:
        for mode in ("ml", "or", "contextual"):
            metrics = aggregate(bundle, selection_seeds, threshold, mode)
            candidates.append({"mode": mode, "threshold": threshold,
                               "metrics": metrics,
                               "eligible": metrics["recall"] >= required_recall})
    eligible = [c for c in candidates if c["eligible"]]
    def utility(candidate):
        m = candidate["metrics"]
        # Round only for stable near-ties; do not favor any named model.
        return (round(m["f1"], 12), round(m["recall"], 12), -m["fp"])
    winner = max(eligible, key=utility)
    validation_by_mode = {
        mode: aggregate(bundle, selection_seeds, winner["threshold"], mode)
        for mode in ("rules", "ml", "or", "contextual")
    }
    return {"selected_mode": winner["mode"], "threshold": winner["threshold"],
            "selection_metrics": winner["metrics"],
            "reference_metrics": reference,
            "validation_by_mode": validation_by_mode,
            "selection_seeds": list(selection_seeds),
            "minimum_recall": float(required_recall),
            "selection_policy": "Highest validation F1 among candidates meeting rules-baseline recall; tie-break on recall and fewer false positives.",
            "candidate_count": len(candidates),
            "eligible_candidate_count": len(eligible),
            "candidate_results": candidates}


def benchmark(selection_seeds=(151,152,153,154,155),
              test_seeds=(301,302,303,304,305)):
    if set(selection_seeds)&set(test_seeds):
        raise ValueError("Selection and final test seeds must be disjoint")
    bundle,_ = baseline()
    choice=select_configuration(bundle,selection_seeds)
    threshold=choice["threshold"]
    return {"selection":choice,"test_seeds":list(test_seeds),
            "held_out":{
                "rules":aggregate(bundle,test_seeds,threshold,"rules"),
                "ml":aggregate(bundle,test_seeds,threshold,"ml"),
                "or":aggregate(bundle,test_seeds,threshold,"or"),
                "contextual":aggregate(bundle,test_seeds,threshold,"contextual"),
                "selected":aggregate(bundle,test_seeds,threshold,choice["selected_mode"])
            }}

if __name__=="__main__":
    import json
    print(json.dumps(benchmark(),indent=2))
