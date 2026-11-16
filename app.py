"""Run with: streamlit run app.py"""
import json
from pathlib import Path
import pandas as pd
import streamlit as st
from src.pipeline import generate_events, extract_features, detect, evaluate

st.set_page_config(page_title='Cloud Threat Detector PoC', layout='wide')
st.title('AI Cloud Threat Detector — Synthetic Proof of Concept')
st.caption('Research demonstration only. Synthetic logs; not validated on production systems.')
seed=st.sidebar.number_input('Random seed',min_value=0,value=42)
rows=detect(extract_features(generate_events(seed=int(seed))),seed=int(seed))
metrics=evaluate(rows)
a,b,c,d=st.columns(4)
a.metric('Detection windows',len(rows));b.metric('Flagged windows',sum(r['alert'] for r in rows));c.metric('Precision (synthetic)',metrics['precision']);d.metric('Recall (synthetic)',metrics['recall'])
st.subheader('Flagged activity')
df=pd.DataFrame([{k:v for k,v in r.items() if k!='event_ids'} for r in rows if r['alert']])
st.dataframe(df,use_container_width=True)
st.download_button('Download detection results',json.dumps(rows,indent=2),'detections.json','application/json')
st.subheader('Evaluation confusion matrix')
st.json(metrics)
st.warning('Metrics are illustrative and optimistic: the benign baseline and evaluation come from the same synthetic generator. External held-out datasets and prospective testing are needed before making effectiveness claims.')
