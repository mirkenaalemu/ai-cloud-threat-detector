"""Synthetic research dashboard. No live telemetry or production security controls."""
import json
import pandas as pd
import streamlit as st
from src.pipeline import generate_events, extract_features, detect as detect_v1, evaluate
from src.v2 import make_dataset, train_detector, detect_v2
from src.v3 import fit_autoencoder, detect_v3, compare
from src.v5 import benchmark as benchmark_v5, risk_detect as detect_v5
from src.v5_2 import benchmark as benchmark_v5_2
from src.cloudtrail_import import extract_unlabeled_windows, MAX_BYTES
from src.v4 import (baseline, detect as detect_v4, demo as compare_v4,
                    record_review, eligible_benign, verify_ledger,
                    build_candidate, promote, rollback)

st.set_page_config(page_title="AI Cloud Threat Detector", layout="wide")
st.title("AI Cloud Threat Detector — Synthetic Research Prototype")
st.warning("Synthetic-data research demo only. Not a production security monitor, authenticated analyst system or real-world validation.")
version=st.sidebar.radio("Detector",["Version 5 — context-aware detection",
                                    "Version 4 — safe adaptive learning demo",
                                    "Version 3 — experimental neural model",
                                    "Version 2 — evidence-gated",
                                    "Version 1 — baseline"])
seed=st.sidebar.number_input("Evaluation seed",min_value=0,value=101)
if version.startswith("Version 5"):
    st.caption("V5: context-aware detection with validation-selected configuration and held-out synthetic benchmarks.")
    @st.cache_resource(show_spinner="Computing V5.1 validation and held-out benchmarks...")
    def get_v5_1_benchmark(cache_schema="v5.1-selection-audit-1"):
        # New cache identity prevents a V5 result from being reused by V5.1.
        return baseline()[0], benchmark_v5()
    v5_bundle, v5_report = get_v5_1_benchmark()
    required_selection_fields = {
        "selection_policy", "minimum_recall", "eligible_candidate_count",
        "candidate_count", "validation_by_mode", "candidate_results"
    }
    if not required_selection_fields.issubset(v5_report.get("selection", {})):
        get_v5_1_benchmark.clear()
        v5_bundle, v5_report = get_v5_1_benchmark()
    choice = v5_report["selection"]
    selected_mode, threshold = choice["selected_mode"], choice["threshold"]
    st.write("Validation-selected configuration:", selected_mode)
    st.caption(choice["selection_policy"])
    st.caption(f"Validation recall floor: {choice['minimum_recall']:.1%}; "
               f"eligible candidates: {choice['eligible_candidate_count']} of {choice['candidate_count']}.")
    mode = st.sidebar.selectbox("V5 detection mode", ["selected", "rules", "ml", "or", "contextual"])
    actual_mode = selected_mode if mode == "selected" else mode
    if mode != "selected":
        st.info(f"Manual demonstration mode: {mode}. Automatic validation selection remains {selected_mode}.")
    st.subheader("Validation comparison — model selection")
    st.caption("Validation seeds 151–155 are used to select a configuration. These metrics are distinct from the final holdout.")
    st.dataframe(pd.DataFrame(choice["validation_by_mode"]).T, use_container_width=True)
    with st.expander("Inspect threshold candidates and selection decision"):
        candidates = pd.DataFrame([
            {"mode": c["mode"], "threshold": c["threshold"],
             "eligible": c["eligible"], **c["metrics"]}
            for c in choice["candidate_results"]])
        st.dataframe(candidates.sort_values(["f1", "recall"], ascending=False),
                     use_container_width=True)
        st.caption("Candidate thresholds and model choice use validation data only.")
    st.subheader("Held-out synthetic comparison — final evaluation")
    st.caption("Final evaluation uses disjoint seeds 301–305. Holdout results do not determine the automatic selection.")
    st.dataframe(pd.DataFrame(v5_report["held_out"]).T, use_container_width=True)
    st.subheader("V5.2 — synthetic robustness evaluation")
    st.caption("Additional disjoint seeds 401–420; fixed V5.1 model selection. "
               "Stress scenarios are simulated, not independently sourced cloud attacks.")
    @st.cache_data(show_spinner="Running V5.2 scenario evaluation...")
    def get_v5_2_report():
        return benchmark_v5_2()
    if st.button("Run V5.2 robustness tests"):
        st.session_state["show_v5_2"] = True
    if st.session_state.get("show_v5_2"):
        robustness = get_v5_2_report()
        overview = []
        for scenario_name, comparisons in robustness["scenarios"].items():
            for name, metrics in comparisons.items():
                overview.append({"scenario": scenario_name, "mode": name,
                                 **{k: metrics[k] for k in
                                    ("tp", "fp", "fn", "tn", "precision", "recall", "f1")},
                                 "f1_bootstrap_95pct":
                                     str(metrics["seed_cluster_bootstrap_95pct"]["f1"])})
        st.dataframe(pd.DataFrame(overview), use_container_width=True)
        st.download_button("Download V5.2 evaluation JSON",
                           json.dumps(robustness, indent=2),
                           "v5_2_robustness.json", "application/json")
        st.caption(robustness["limitations"])
    st.subheader("Authorized CloudTrail JSON export")
    st.caption("Use only authorized, sanitized exports. Avoid uploading sensitive logs to this public demonstration.")
    uploaded = st.file_uploader("CloudTrail JSON (up to 5 MB)", type=["json"], key="v5_cloudtrail")
    imported = uploaded is not None
    if imported:
        if uploaded.size > MAX_BYTES:
            st.error("File exceeds 5 MB.")
            st.stop()
        try:
            source_rows = extract_unlabeled_windows(uploaded.getvalue())
        except (ValueError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            st.error(f"Invalid or unsupported CloudTrail export: {exc}")
            st.stop()
        if not source_rows:
            st.warning("No supported CloudTrail events found.")
            st.stop()
    else:
        source_rows = extract_features(make_dataset(seed=int(seed)))
    rows = detect_v5(source_rows, v5_bundle, threshold, actual_mode)
    if imported:
        st.subheader("Imported event detections")
        st.metric("Windows", len(rows))
        st.metric("Alerts", sum(r["alert"] for r in rows))
        st.dataframe(pd.DataFrame([{k:v for k,v in r.items() if k != "event_ids"}
                                    for r in rows if r["alert"]]), use_container_width=True)
        st.download_button("Download detections", json.dumps(rows, indent=2),
                           "cloudtrail_detections.json", "application/json")
        st.caption("Imported events have no verified attack labels; precision and recall are not calculated.")
        st.stop()
elif version.startswith("Version 4"):
    st.caption("V4: stable Isolation Forest with human-approval workflow simulation, model gates and in-session rollback. No autonomous retraining.")
    @st.cache_resource
    def get_v4():
        return baseline()
    base,calibration=get_v4()
    if "v4_registry" not in st.session_state:
        st.session_state.v4_registry={"active":base,"previous":None,"version":1}
    if "v4_ledger" not in st.session_state:
        st.session_state.v4_ledger=[]
    registry=st.session_state.v4_registry
    mode=st.sidebar.selectbox("V4 alert mode",["rules","ml","hybrid"])
    rows=detect_v4(extract_features(make_dataset(seed=int(seed))),registry["active"],mode)
    st.subheader("Same-data synthetic comparison")
    st.dataframe(pd.DataFrame(compare_v4(seed=int(seed))).T,use_container_width=True)
    st.subheader("Review and model lifecycle simulation")
    st.info("All reviewers below are simulated. This is an in-memory session demonstration; it does not authenticate analysts, retain reviews across restarts, or retrain from real customer data.")
    st.write("Active in-session model version:",registry["version"])
    if st.button("Simulate two reviewers approving 30 synthetic benign windows"):
        pool=extract_features(generate_events(seed=61,benign=300,malicious=0))
        ledger=st.session_state.v4_ledger
        for row in pool[:30]:
            for reviewer in ("demo-reviewer-a","demo-reviewer-b"):
                try:
                    ledger=record_review(ledger,row,reviewer,"confirmed_benign",
                                         "Synthetic benign example for workflow demonstration")
                except ValueError as exc:
                    if "One decision per reviewer" not in str(exc):
                        raise
        st.session_state.v4_ledger=ledger
        st.success("Simulated review entries recorded in this session.")
    ledger=st.session_state.v4_ledger
    st.write("Audit-chain integrity:", "verified" if verify_ledger(ledger) else "invalid")
    st.write("Eligible doubly-reviewed benign windows:",len(eligible_benign(ledger)))
    if st.button("Train and validate candidate (explicit demo approval)"):
        try:
            st.session_state.v4_candidate=build_candidate(
                ledger,registry["active"],calibration,approved_by="demo-training-approver")
            st.success("Candidate created. Promotion is NOT automatic.")
        except (ValueError,PermissionError) as exc:
            st.error(str(exc))
    candidate=st.session_state.get("v4_candidate")
    if candidate:
        st.json(candidate["evaluation"])
        if st.button("Approve candidate promotion",disabled=not candidate["evaluation"]["passed"]):
            try:
                st.session_state.v4_registry=promote(registry,candidate,"demo-independent-approver")
                st.session_state.pop("v4_candidate",None)
                st.success("In-session model promoted. Previous model available for rollback.")
                st.rerun()
            except (ValueError,PermissionError) as exc:
                st.error(str(exc))
    if st.button("Rollback in-session model",disabled=registry.get("previous") is None):
        st.session_state.v4_registry=rollback(registry,"demo-rollback-approver")
        st.success("Previous model restored in this session.")
        st.rerun()
elif version.startswith("Version 3"):
    mode=st.sidebar.selectbox("V3 alert mode",["rules","neural","hybrid"])
    @st.cache_resource
    def get_v3():
        return fit_autoencoder()
    bundle=get_v3()
    rows=detect_v3(extract_features(make_dataset(seed=int(seed))),bundle,mode=mode)
    st.caption("V3: experimental neural network. Numerical warnings may occur; do not rely on these metrics for real-world claims.")
    st.subheader("Same-data ablation")
    st.dataframe(pd.DataFrame(compare(seed=int(seed),bundle=bundle)).T,use_container_width=True)
elif version.startswith("Version 2"):
    @st.cache_resource
    def get_v2():
        return train_detector()
    model,threshold=get_v2()
    rows=detect_v2(extract_features(make_dataset(seed=int(seed))),model,threshold)
    st.caption("V2: rules trigger alerts; ML anomaly scores are informational.")
else:
    rows=detect_v1(extract_features(generate_events(seed=int(seed))),seed=int(seed))
    st.caption("V1 uses different synthetic data; cross-version metrics are not directly comparable.")
metrics=evaluate(rows)
a,b,c,d=st.columns(4)
a.metric("Windows",len(rows))
b.metric("Alerts",sum(r["alert"] for r in rows))
c.metric("Precision (synthetic)",f"{metrics['precision']:.1%}")
d.metric("Recall (synthetic)",f"{metrics['recall']:.1%}")
st.subheader("Flagged windows")
st.dataframe(pd.DataFrame([{k:v for k,v in r.items() if k!="event_ids"} for r in rows if r["alert"]]),use_container_width=True)
st.download_button("Download synthetic results",json.dumps(rows,indent=2),"detections.json","application/json")
st.subheader("Evaluation")
st.json(metrics)
st.caption("Synthetic test labels are used for evaluation only. This demo does not establish deployment readiness, cybersecurity effectiveness, or petitioner authorship.")
