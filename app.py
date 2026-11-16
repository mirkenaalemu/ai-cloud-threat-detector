"""Run with: python -m streamlit run app.py"""
import json
import pandas as pd
import streamlit as st
from src.pipeline import generate_events, extract_features, detect, evaluate
from src.v2 import make_dataset, train_detector, detect_v2
from src.v3 import fit_autoencoder, detect_v3, compare

st.set_page_config(page_title="AI Cloud Threat Detector", layout="wide")
st.title("AI Cloud Threat Detector — Synthetic Research Prototype")
st.warning("Synthetic-only research demonstration. Not a production security monitor or externally validated.")
version = st.sidebar.radio("Detector", [
    "Version 3 — experimental neural model",
    "Version 2 — evidence-gated",
    "Version 1 — baseline"])
seed = st.sidebar.number_input("Evaluation seed", min_value=0, value=101)

if version.startswith("Version 3"):
    mode = st.sidebar.selectbox("V3 alert mode", ["rules", "neural", "hybrid"])
    @st.cache_resource(show_spinner="Training experimental neural model...")
    def get_v3():
        return fit_autoencoder()
    bundle = get_v3()
    rows = detect_v3(extract_features(make_dataset(seed=int(seed))), bundle, mode=mode)
    st.caption("V3: neural autoencoder with 2-neuron bottleneck. No automatic retraining; no live AWS data.")
    st.subheader("Same-data ablation comparison")
    st.dataframe(pd.DataFrame(compare(seed=int(seed), bundle=bundle)).T, use_container_width=True)
elif version.startswith("Version 2"):
    @st.cache_resource
    def get_v2():
        return train_detector()
    model, threshold = get_v2()
    rows = detect_v2(extract_features(make_dataset(seed=int(seed))), model, threshold)
    st.caption("V2: separate benign training/calibration seeds. ML-only anomalies are informational.")
else:
    rows = detect(extract_features(generate_events(seed=int(seed))), seed=int(seed))
    st.caption("V1: original baseline. V1 and V2/V3 use different synthetic scenarios, so results are not directly comparable.")
metrics = evaluate(rows)
a, b, c, d = st.columns(4)
a.metric("Windows", len(rows))
b.metric("Alerts", sum(r["alert"] for r in rows))
c.metric("Precision (synthetic)", f"{metrics['precision']:.1%}")
d.metric("Recall (synthetic)", f"{metrics['recall']:.1%}")
st.subheader("Flagged windows")
st.dataframe(pd.DataFrame([{k:v for k,v in row.items() if k != "event_ids"} for row in rows if row["alert"]]), use_container_width=True)
st.download_button("Download results", json.dumps(rows, indent=2), "detections.json", "application/json")
st.subheader("Evaluation")
st.json(metrics)
st.caption("Labels are for synthetic evaluation only. The attack scenarios are not independently validated. The V3 retraining function creates a candidate model only after explicit approval; this dashboard does not retrain models.")
