from fastapi import FastAPI,HTTPException
from .compiler import compile_jocky,pretty_ir
from .detector import analyze
from .models import CompileRequest,AnalyzeRequest,AnalysisResult
from .sample_data import sample_events

app=FastAPI(title="JOCKY-X Forensic Detection API",version="0.1.0")

@app.get("/health")
def health(): return {"status":"ok","project":"JOCKY-X","mode":"defensive-prototype"}

@app.post("/compile")
def compile(req:CompileRequest):
    try:
        ir=compile_jocky(req.source); return {"valid":True,"ir":ir,"pretty":pretty_ir(ir)}
    except ValueError as e: raise HTTPException(status_code=400,detail=str(e))

@app.post("/analyze",response_model=AnalysisResult)
def run(req:AnalyzeRequest):
    events=req.events or sample_events()
    return analyze([e for e in events if e.platform.lower()==req.platform.lower()])

@app.get("/demo",response_model=AnalysisResult)
def demo(): return analyze(sample_events())

@app.get("/sample-events")
def samples(): return [e.model_dump() for e in sample_events()]
