"""V5.2: reproducible, out-of-selection synthetic robustness evaluation.

Fixed V5.1 selection policy. No test data is used to choose thresholds.
Scenarios are controlled perturbations of the existing synthetic generator;
they are not independently collected or real-world attacks.
"""
import json
import random
from pathlib import Path
from src.pipeline import extract_features, evaluate
from src.v2 import make_dataset
from src.v4 import baseline
from src.v5 import risk_detect, select_configuration

SCENARIOS = ("standard", "benign_admin_burst", "low_and_slow", "volume_shift")
TEST_SEEDS = tuple(range(401, 421))


def scenario_events(seed, scenario):
    if scenario not in SCENARIOS:
        raise ValueError("Unknown synthetic scenario")
    events = make_dataset(seed=seed)
    if scenario == "standard":
        return events
    rng = random.Random(seed + 5200)
    if scenario == "benign_admin_burst":
        # Legitimate maintenance burst deliberately resembles privileged misuse.
        for n in range(12):
            for k in range(3):
                events.append({
                    "event_id": f"admin-{seed}-{n}-{k}",
                    "time": f"2026-02-02T{n:02d}:00:{k:02d}+00:00",
                    "principal": f"approved-admin-{n}",
                    "source_ip": "10.20.0.5",
                    "action": "AttachUserPolicy", "success": True, "label": 0})
    elif scenario == "low_and_slow":
        # Replace existing high-signal attack bursts with isolated actions.
        # All eight stealth events in the original dataset remain untouched.
        for event in events:
            if event["principal"].startswith("attack-"):
                event["time"] = f"2026-02-03T{int(event['event_id'].split('-')[-2]) % 24:02d}:{int(event['event_id'].split('-')[-1])*10:02d}:00+00:00"
                # Grouping is still by principal; one event per 10-minute window.
    elif scenario == "volume_shift":
        # Add diverse legitimate activity, without changing threat labels.
        for n in range(240):
            events.append({
                "event_id": f"shift-{seed}-{n}",
                "time": f"2026-02-04T{n//60:02d}:{n%60:02d}:00+00:00",
                "principal": f"shift-user-{rng.randrange(8)}",
                "source_ip": f"10.30.0.{rng.randrange(1,30)}",
                "action": rng.choice(("ListBuckets", "GetObject", "DescribeInstances")),
                "success": True, "label": 0})
    return events


def exact_metrics(rows):
    m = evaluate(rows)
    # Calculate unrounded values for uncertainty analysis.
    tp, fp, fn = m["tp"], m["fp"], m["fn"]
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {**m, "precision": p, "recall": r,
            "f1": 2*p*r/(p+r) if p+r else 0.0}


def _interval(values, confidence=0.95):
    ordered = sorted(values)
    lo = int(((1-confidence)/2) * (len(ordered)-1))
    hi = int(((1+confidence)/2) * (len(ordered)-1))
    return [round(ordered[lo], 4), round(ordered[hi], 4)]


def bootstrap_by_seed(per_seed, draws=1000, bootstrap_seed=5202):
    """Seed-cluster bootstrap; not an independent real-world confidence interval."""
    if len(per_seed) < 2 or draws < 10:
        raise ValueError("At least two seeds and ten bootstrap draws required")
    rng = random.Random(bootstrap_seed)
    sampled = {"precision": [], "recall": [], "f1": []}
    for _ in range(draws):
        batch = [rng.choice(per_seed) for _ in per_seed]
        tp = sum(m["tp"] for m in batch)
        fp = sum(m["fp"] for m in batch)
        fn = sum(m["fn"] for m in batch)
        p = tp/(tp+fp) if tp+fp else 0.0
        r = tp/(tp+fn) if tp+fn else 0.0
        f = 2*p*r/(p+r) if p+r else 0.0
        for key, value in (("precision",p),("recall",r),("f1",f)):
            sampled[key].append(value)
    return {key: _interval(vals) for key, vals in sampled.items()}


def benchmark(seeds=TEST_SEEDS, scenarios=SCENARIOS, bootstrap_draws=1000):
    if not seeds or len(set(seeds)) != len(seeds):
        raise ValueError("Unique test seeds required")
    if set(seeds) & {151,152,153,154,155,301,302,303,304,305,11,12}:
        raise ValueError("V5.2 seeds must not overlap training, validation or V5.1 holdout")
    if not scenarios or len(set(scenarios)) != len(scenarios):
        raise ValueError("Unique scenarios required")
    bundle, _ = baseline()
    selection = select_configuration(bundle)
    threshold, selected = selection["threshold"], selection["selected_mode"]
    report = {}
    for scenario in scenarios:
        if scenario not in SCENARIOS:
            raise ValueError("Unknown synthetic scenario")
        per_mode = {mode: [] for mode in ("rules", "selected")}
        for seed in seeds:
            rows = extract_features(scenario_events(seed, scenario))
            for mode, actual in (("rules","rules"),("selected",selected)):
                result = exact_metrics(risk_detect(rows,bundle,threshold,actual))
                per_mode[mode].append({"seed":seed,"windows":len(rows),**result})
        summary = {}
        for mode, records in per_mode.items():
            tp = sum(x["tp"] for x in records)
            fp = sum(x["fp"] for x in records)
            fn = sum(x["fn"] for x in records)
            tn = sum(x["tn"] for x in records)
            p = tp/(tp+fp) if tp+fp else 0.0
            r = tp/(tp+fn) if tp+fn else 0.0
            summary[mode] = {
                "tp":tp,"fp":fp,"fn":fn,"tn":tn,
                "precision":round(p,4),"recall":round(r,4),
                "f1":round(2*p*r/(p+r),4) if p+r else 0.0,
                "seed_cluster_bootstrap_95pct":bootstrap_by_seed(records,draws=bootstrap_draws),
                "per_seed":records}
        report[scenario] = summary
    return {
        "version":"5.2", "selected_mode":selected,
        "selection_seeds":[151,152,153,154,155],
        "previous_holdout_seeds":[301,302,303,304,305],
        "stress_test_seeds":list(seeds),
        "method":"Fixed validation-selected detector versus rules on disjoint synthetic scenario seeds",
        "limitations":"All scenarios are generated by project code. Seed bootstrap captures only variability across these synthetic draws, not real-world uncertainty.",
        "scenarios":report}


if __name__ == "__main__":
    output = Path("results/v5_2_robustness.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    result = benchmark()
    output.write_text(json.dumps(result, indent=2))
    print(json.dumps({"output":str(output),"selected_mode":result["selected_mode"],
                      "summary":{s:{m:{k:v for k,v in d.items() if k!="per_seed"}
                                    for m,d in modes.items()}
                                 for s,modes in result["scenarios"].items()}}, indent=2))
