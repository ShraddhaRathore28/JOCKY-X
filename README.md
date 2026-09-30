# JOCKY-X
Defensive SIH 2026 prototype: JOCKY forensic DSL -> cross-platform IR -> 8 behavioral detection engines -> explainable risk -> timeline -> dashboard.

Safety: synthetic/replayed telemetry only. No malware execution, persistence, credential theft, EDR bypass, BYOVD exploitation, process hollowing, injection, or offensive capability.

## Run in VS Code
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

API docs: http://127.0.0.1:8000/docs
Dashboard (second terminal): streamlit run dashboard.py
Tests: pytest -q

Demo: http://127.0.0.1:8000/demo
