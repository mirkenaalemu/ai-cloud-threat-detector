"""V5.3: label-free, per-principal temporal correlation of synthetic event windows.

Thresholds are selected using seeds 501–505, separate from V5.1 and V5.2
evaluation. A new final test uses seeds 601–620. This is a research simulation.
"""
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
from pathlib import Path

from src.pipeline import extract_features
from src.v4 import baseline
from src.v5 import risk_detect, select_configuration
from src.v5_2 import SCENARIOS, scenario_events, exact_metrics, bootstrap_by_seed

VALIDATION_SEEDS = tuple(range(501, 506))
TEST_SEEDS = tuple(range(601, 621))
CANDIDATES = (2, 3, 4, 5, 6)
HORIZON_HOURS = 24


def temporal_features(rows, horizon_hours=HORIZON_HOURS):
    """Attach past-window counts, never using labels or future events."""
    if horizon_hours <= 0:
        raise ValueError("Positive history horizon required")
    histories = defaultdict(deque)
    output = []
    ordered = sorted(enumerate(rows), key=lambda x: (datetime.fromisoformat(x[1]["window"]), x[0]))
    results = {}
    horizon = timedelta(hours=horizon_hours)
    for index, row in ordered:
        now = datetime.fromisoformat(row["window"])
        history = histories[row["principal"]]
        while history and now - history[0][0] >= horizon:
            history.popleft()
        # Current window is included in the temporal evidence.
        history.append((now, row))
        results[index] = {
            **row,
            "history_windows": len(history),
            "history_failed_logins": sum(int(r["failed_logins"]) for _, r in history),
            "history_privileged_changes": sum(int(r["privileged_changes"]) for _, r in history),
            "history_distinct_windows": len({t for t, _ in history}),
        }
    return [results[i] for i in range(len(rows))]


def detect_temporal(rows, bundle, threshold, base_mode, min_evidence=4):
    """Escalate sustained failure or privilege evidence on top of V5.1 selection."""
    if min_evidence not in CANDIDATES:
        raise ValueError("Unsupported temporal evidence threshold")
    enriched = temporal_features(rows)
    baseline_rows = risk_detect(enriched, bundle, threshold, base_mode)
    out = []
    for row in baseline_rows:
        sustained = (
            row["history_distinct_windows"] >= 2
            and (row["history_failed_logins"] >= min_evidence
                 or row["history_privileged_changes"] >= min_evidence)
        )
        reasons = list(row["reasons"])
        if sustained and not row["alert"]:
            reasons.append(f"Repeated security-sensitive actions across 24h (threshold {min_evidence})")
        out.append({**row, "alert": bool(row["alert"] or sustained), "reasons": reasons,
                    "temporal_escalation": bool(sustained)})
    return out


def _aggregate(records):
    totals = {k: sum(r[k] for r in records) for k in ("tp", "fp", "fn", "tn")}
    tp, fp, fn = totals["tp"], totals["fp"], totals["fn"]
    p = tp/(tp+fp) if tp+fp else 0
    r = tp/(tp+fn) if tp+fn else 0
    return {**totals, "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2*p*r/(p+r), 4) if p+r else 0}


def _evaluate(bundle, choice, seeds, scenarios, evidence_threshold=None, include_per_seed=False,
              bootstrap_draws=200):
    result = {}
    for scenario in scenarios:
        per_seed = {"v5_1_selected": [], "v5_3_temporal": []}
        for seed in seeds:
            windows = extract_features(scenario_events(seed, scenario))
            baseline_rows = risk_detect(windows, bundle, choice["threshold"], choice["selected_mode"])
            per_seed["v5_1_selected"].append({"seed": seed, **exact_metrics(baseline_rows)})
            if evidence_threshold is not None:
                enhanced = detect_temporal(windows, bundle, choice["threshold"],
                                           choice["selected_mode"], evidence_threshold)
                per_seed["v5_3_temporal"].append({"seed": seed, **exact_metrics(enhanced)})
        summary = {}
        for mode, records in per_seed.items():
            if not records:
                continue
            summary[mode] = _aggregate(records)
            if include_per_seed:
                summary[mode]["per_seed"] = records
                summary[mode]["seed_cluster_bootstrap_95pct"] = bootstrap_by_seed(
                    records, draws=bootstrap_draws, bootstrap_seed=5303)
        result[scenario] = summary
    return result


def select_temporal_threshold(bundle, choice, validation_seeds=VALIDATION_SEEDS):
    if not validation_seeds or len(set(validation_seeds)) != len(validation_seeds):
        raise ValueError("Unique validation seeds required")
    records = []
    for threshold in CANDIDATES:
        results = _evaluate(bundle, choice, validation_seeds, SCENARIOS, threshold)
        v5 = _aggregate([results[s]["v5_1_selected"] for s in SCENARIOS])
        v53 = _aggregate([results[s]["v5_3_temporal"] for s in SCENARIOS])
        # Require recall no worse than the original selected model across validation scenarios.
        eligible = v53["recall"] >= v5["recall"]
        records.append({"threshold": threshold, "eligible": eligible,
                        "baseline": v5, "temporal": v53})
    eligible = [r for r in records if r["eligible"]]
    if not eligible:
        return {"selected_threshold": None, "candidates": records,
                "reason": "No candidate met the baseline recall constraint"}
    winner = max(eligible, key=lambda r: (r["temporal"]["f1"], -r["temporal"]["fp"],
                                          r["threshold"]))
    # Only promote when validation F1 exceeds baseline; otherwise preserve baseline.
    improved = winner["temporal"]["f1"] > winner["baseline"]["f1"]
    return {"selected_threshold": winner["threshold"] if improved else None,
            "candidates": records,
            "reason": "Improved validation F1" if improved else "No validation F1 improvement; baseline retained"}


def benchmark(validation_seeds=VALIDATION_SEEDS, test_seeds=TEST_SEEDS,
              bootstrap_draws=200):
    reserved = {11, 12, 151, 152, 153, 154, 155, 301, 302, 303, 304, 305} | set(range(401,421))
    if not validation_seeds or not test_seeds or len(set(validation_seeds)) != len(validation_seeds) or len(set(test_seeds)) != len(test_seeds):
        raise ValueError("Unique nonempty seeds required")
    if set(validation_seeds) & (set(test_seeds) | reserved) or set(test_seeds) & reserved:
        raise ValueError("Training, previous evaluations, validation and final test must be disjoint")
    if len(test_seeds) < 2:
        raise ValueError("At least two final test seeds needed for bootstrap")
    bundle, _ = baseline()
    choice = select_configuration(bundle)
    selected = select_temporal_threshold(bundle, choice, validation_seeds)
    threshold = selected["selected_threshold"]
    results = _evaluate(bundle, choice, test_seeds, SCENARIOS, threshold,
                        include_per_seed=True, bootstrap_draws=bootstrap_draws)
    return {"version": "5.3", "validation_seeds": list(validation_seeds),
            "test_seeds": list(test_seeds),
            "selection": selected, "base_mode": choice["selected_mode"],
            "history_hours": HORIZON_HOURS, "results": results,
            "limitations": "All attack and benign scenarios are synthetic. Long-term counts are per principal and may create legitimate administrator alerts. Bootstrap intervals reflect seed-to-seed simulation variation only."}


if __name__ == "__main__":
    result = benchmark()
    path = Path("results/v5_3_temporal.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2))
    print(json.dumps({"output": str(path), "selection": result["selection"],
                      "summary": {s: {k: {metric: v for metric, v in val.items()
                                            if metric not in ("per_seed", "seed_cluster_bootstrap_95pct")}
                                      for k, val in modes.items()}
                                  for s, modes in result["results"].items()}}, indent=2))
