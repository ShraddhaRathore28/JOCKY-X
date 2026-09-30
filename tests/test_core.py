from app.compiler import compile_jocky
from app.detector import analyze
from app.sample_data import sample_events

def test_compile():
    s="""INVESTIGATION test
TARGET windows,ubuntu
COLLECT process,network
DETECT process_anomaly,beaconing
TIMELINE true
EXPLAIN true"""
    x=compile_jocky(s)
    assert x["investigation"]=="test"
    assert "beaconing" in x["detect"]

def test_detection():
    x=analyze(sample_events())
    assert x["event_count"]>0
    assert x["risk_score"]>0
    assert x["findings"]

def test_empty():
    x=analyze([])
    assert x["risk_score"]==0
    assert x["verdict"]=="NO FINDINGS"
