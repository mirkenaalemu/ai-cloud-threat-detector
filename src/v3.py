"""V3 experimental neural autoencoder and review-gated model updates.

Research-only: uses synthetic data. No unattended learning or live response.
"""
import json
from pathlib import Path
import numpy as np
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from src.pipeline import extract_features, generate_events, evaluate
from src.v2 import FEATURES, make_dataset

def matrix(rows):
    if not rows:
        raise ValueError("No feature windows")
    return np.asarray([[r[k] for k in FEATURES] for r in rows], dtype=float)

def fit_autoencoder(seed=11, calibration_seed=12, budget=0.02):
    """Train a small nonlinear neural network to reconstruct normal features.

    A 2-neuron hidden layer is a bottleneck for four input features.
    Labels are never passed to the neural network.
    """
    if not 0 < budget < 0.5:
        raise ValueError("budget must be between 0 and 0.5")
    train = extract_features(generate_events(seed=seed, benign=1200, malicious=0))
    calibration = extract_features(generate_events(seed=calibration_seed, benign=1200, malicious=0))
    scaler = StandardScaler().fit(matrix(train))
    x = scaler.transform(matrix(train))
    cal = scaler.transform(matrix(calibration))
    net = MLPRegressor(hidden_layer_sizes=(2,), activation="tanh", solver="lbfgs",
                       max_iter=400, random_state=42, alpha=0.01)
    net.fit(x, x)
    cal_loss = np.mean((net.predict(cal) - cal)**2, axis=1)
    threshold = float(np.quantile(cal_loss, 1-budget))
    return {"scaler":scaler, "model":net, "threshold":threshold,
            "training_seed":seed, "calibration_seed":calibration_seed}

def score(rows, bundle):
    x = bundle["scaler"].transform(matrix(rows))
    return np.mean((bundle["model"].predict(x)-x)**2, axis=1)

def rules(row):
    reasons = []
    if row["failed_logins"] >= 3: reasons.append("3+ failed logins")
    if row["privileged_changes"] >= 2: reasons.append("2+ privileged changes")
    if row["count"] >= 12: reasons.append("12+ events")
    return reasons

def detect_v3(rows, bundle, mode="hybrid"):
    """Compare rules, neural model and hybrid on IDENTICAL windows.

    Hybrid means either rule evidence or calibrated neural anomaly; it is
    experimental and can increase false positives.
    """
    if mode not in ("rules", "neural", "hybrid"):
        raise ValueError("mode must be rules, neural or hybrid")
    losses = score(rows, bundle)
    output = []
    for row, loss in zip(rows, losses):
        evidence = rules(row)
        neural = bool(loss > bundle["threshold"])
        alert = bool(evidence) if mode=="rules" else neural if mode=="neural" else bool(evidence) or neural
        output.append({**row, "reconstruction_error":round(float(loss), 5),
                       "neural_anomaly":neural, "alert":alert,
                       "reasons":evidence + (["Neural reconstruction anomaly"] if neural else [])})
    return output

def compare(seed=101, bundle=None):
    """Apples-to-apples V3 ablation; no test-label training."""
    bundle = bundle if bundle is not None else fit_autoencoder()
    rows = extract_features(make_dataset(seed=seed))
    return {mode:evaluate(detect_v3(rows, bundle, mode))
            for mode in ("rules","neural","hybrid")}

def drift_report(reference_rows, candidate_rows):
    """Simple standardized mean shift, NOT a complete drift test."""
    ref, new = matrix(reference_rows), matrix(candidate_rows)
    scale = np.maximum(np.std(ref, axis=0), 1.0)
    shift = np.abs(np.mean(new, axis=0)-np.mean(ref, axis=0))/scale
    return {"per_feature":dict(zip(FEATURES, [round(float(x), 4) for x in shift])),
            "max_standardized_shift":round(float(np.max(shift)), 4),
            "review_recommended":bool(np.max(shift)>1.0)}

def review_gated_retrain(reviewed_rows, current_bundle, approval=False, minimum=100):
    """Build candidate only with explicit approval and human-reviewed benign rows.

    Does not replace or deploy the active model. Caller must evaluate candidate
    on independent held-out data and explicitly promote it separately.
    """
    if not approval:
        raise PermissionError("Explicit analyst approval required")
    clean = [r for r in reviewed_rows if r.get("review_status")=="confirmed_benign"]
    if len(clean)<minimum:
        raise ValueError("Insufficient analyst-reviewed benign windows")
    scaler = StandardScaler().fit(matrix(clean))
    x = scaler.transform(matrix(clean))
    net = MLPRegressor(hidden_layer_sizes=(2,), activation="tanh", solver="lbfgs",
                       max_iter=400, random_state=42, alpha=0.01)
    net.fit(x,x)
    loss = np.mean((net.predict(x)-x)**2, axis=1)
    return {"scaler":scaler, "model":net,
            "threshold":float(np.quantile(loss, 0.98)),
            "status":"candidate_only", "training_rows":len(clean)}

if __name__=="__main__":
    print(json.dumps({"synthetic_seed":101,"metrics":compare()},indent=2))
