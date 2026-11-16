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
    """Select on validation scenarios, never on final evaluation scenarios.

    Conservative fallback is rules-only when no hybrid candidate dominates it.
    """
    if not selection_seeds:
        raise ValueError("Selection seeds required")
    reference = aggregate(bundle, selection_seeds, bundle["threshold"], "rules")
    # Candidate thresholds derived only from independent benign calibration
    # would be ideal; this search uses validation labels for model selection,
    # with a completely separate final holdout.
    calibration_rows = extract_features(make_dataset(seed=149))
    candidate_scores = sorted(set(float(x) for x in score(calibration_rows, bundle)))
    quantiles = (0.005, 0.01, 0.02, 0.04, 0.08, 0.12)
    import numpy as np
    thresholds = [float(np.quantile(candidate_scores, q)) for q in quantiles]
    candidates = [{"mode":"rules","threshold":bundle["threshold"],"metrics":reference}]
    for threshold in thresholds:
        for mode in ("contextual","or"):
            metrics = aggregate(bundle,selection_seeds,threshold,mode)
            if metrics["recall"] >= max(minimum_recall, reference["recall"]):
                candidates.append({"mode":mode,"threshold":threshold,"metrics":metrics})
    # Prioritize recall, but never increase false alerts relative to rules unless
    # a real recall improvement compensates. This is a stated engineering choice.
    def utility(c):
        m=c["metrics"]
        return (m["f1"], m["recall"], -m["fp"])
    winner=max(candidates,key=utility)
    return {"selected_mode":winner["mode"],"threshold":winner["threshold"],
            "selection_metrics":winner["metrics"],
            "reference_metrics":reference,
            "selection_seeds":list(selection_seeds),
            "candidate_count":len(candidates)}

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
