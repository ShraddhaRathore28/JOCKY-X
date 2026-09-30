import requests
import pandas as pd
import streamlit as st

API="http://127.0.0.1:8000"
st.set_page_config(page_title="JOCKY-X",layout="wide")
st.title("JOCKY-X")
st.caption("Cross-Platform Forensic Detection & Investigation — defensive prototype")
try:
    requests.get(API+"/health",timeout=2).raise_for_status()
except Exception:
    st.error("Start API first: uvicorn app.main:app --reload")
    st.stop()

d=requests.get(API+"/demo").json()
a,b,c=st.columns(3)
a.metric("Risk Score",d["risk_score"])
b.metric("Verdict",d["verdict"])
c.metric("Events",d["event_count"])

st.divider()
st.subheader("Detection Findings")
if d["findings"]:
    st.dataframe(pd.DataFrame(d["findings"])[["engine","severity","score","title","reason","attack_techniques"]],use_container_width=True,hide_index=True)

st.subheader("Incident Timeline")
st.dataframe(pd.DataFrame(d["timeline"]),use_container_width=True,hide_index=True)

st.subheader("JOCKY → IR")
source="""INVESTIGATION demo_case
TARGET windows,ubuntu
COLLECT process,network,file,memory
DETECT process_anomaly,beaconing,dns_tunneling,file_anomaly,memory_anomaly
TIMELINE true
EXPLAIN true"""
src=st.text_area("JOCKY script",source,height=180)
if st.button("Compile JOCKY"):
    r=requests.post(API+"/compile",json={"source":src})
    if r.ok:
        x=r.json()
        st.success("Compilation successful")
        st.code(x["pretty"])
        st.json(x["ir"])
    else: st.error(r.text)
st.info("Synthetic demo data; prototype thresholds are not production benchmark results.")
