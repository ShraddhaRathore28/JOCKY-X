from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

class CompileRequest(BaseModel):
    source: str

class Event(BaseModel):
    timestamp: str
    platform: str
    event_type: str
    host: str = "demo-host"
    process: Optional[str] = None
    parent_process: Optional[str] = None
    destination: Optional[str] = None
    domain: Optional[str] = None
    bytes_out: int = 0
    file_path: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

class AnalyzeRequest(BaseModel):
    platform: str = "windows"
    events: List[Event] = Field(default_factory=list)

class Finding(BaseModel):
    engine: str
    severity: str
    score: int
    title: str
    reason: str
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    attack_techniques: List[str] = Field(default_factory=list)

class AnalysisResult(BaseModel):
    risk_score: int
    verdict: str
    findings: List[Finding]
    timeline: List[Dict[str, Any]]
    event_count: int
