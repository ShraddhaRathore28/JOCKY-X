from collections import defaultdict
from .models import Finding

def F(engine,severity,score,title,reason,hits,tech):
    return Finding(engine=engine,severity=severity,score=score,title=title,reason=reason,
        evidence=[x.model_dump() for x in hits[:10]],attack_techniques=tech)

def process_anomaly(e):
    h=[x for x in e if x.event_type=="process_start" and (x.parent_process or "").lower() in {"winword.exe","excel.exe","outlook.exe"} and (x.process or "").lower() in {"powershell.exe","cmd.exe","wscript.exe"}]
    return [F("process_anomaly","high",18,"Unusual process ancestry","Interpreter launched from an application parent.",h,["T1059"])] if h else []

def beaconing(e):
    g=defaultdict(list)
    for x in e:
        if x.event_type=="network_connection" and x.destination:g[x.destination].append(x)
    h=[x for v in g.values() if len(v)>=4 for x in v]
    return [F("beaconing","medium",16,"Repeated outbound connection","Repeated connections to one destination.",h,["T1071"])] if h else []

def dns_tunneling(e):
    h=[x for x in e if x.event_type=="dns_query" and x.domain and (len(x.domain)>45 or x.domain.count(".")>=5)]
    return [F("dns_tunneling","high",18,"DNS anomaly","DNS query crosses prototype complexity threshold.",h,["T1071.004"])] if h else []

def file_anomaly(e):
    h=[x for x in e if x.event_type=="file_write" and x.file_path and x.file_path.lower().endswith((".tmp",".dat",".locked"))]
    return [F("file_anomaly","medium",12,"File-write anomaly","File write matches configured forensic rule.",h,["T1105"])] if h else []

def memory_anomaly(e):
    h=[x for x in e if x.event_type=="memory_anomaly"]
    return [F("memory_anomaly","high",15,"Memory anomaly","Synthetic telemetry reports a memory anomaly.",h,["T1055"])] if h else []

def driver_anomaly(e):
    h=[x for x in e if x.event_type=="driver_event" and x.details.get("anomalous")]
    return [F("driver_anomaly","high",14,"Driver anomaly","Synthetic telemetry marks a driver event anomalous.",h,["T1547"])] if h else []

def lateral_movement(e):
    dest={x.destination for x in e if x.event_type=="network_connection" and x.destination}
    h=[x for x in e if x.event_type=="network_connection" and x.destination]
    return [F("lateral_movement","medium",13,"Multiple destinations","Host contacted multiple destinations.",h,["T1021"])] if len(dest)>=3 else []

def data_exfiltration(e):
    h=[x for x in e if x.bytes_out>=5000000]
    return [F("data_exfiltration","high",16,"Large outbound transfer","Outbound bytes exceeded prototype threshold.",h,["T1041"])] if h else []

ENGINES={"process_anomaly":process_anomaly,"beaconing":beaconing,"dns_tunneling":dns_tunneling,
"file_anomaly":file_anomaly,"memory_anomaly":memory_anomaly,"driver_anomaly":driver_anomaly,
"lateral_movement":lateral_movement,"data_exfiltration":data_exfiltration}

def analyze(events,enabled=None):
    findings=[]
    for name in (enabled or list(ENGINES)): findings+=ENGINES[name](events)
    score=min(100,sum(x.score for x in findings))
    verdict="HIGH RISK" if score>=70 else "MEDIUM RISK" if score>=40 else "LOW RISK" if score else "NO FINDINGS"
    timeline=sorted([x.model_dump() for x in events],key=lambda x:x["timestamp"])
    return {"risk_score":score,"verdict":verdict,"findings":[x.model_dump() for x in findings],"timeline":timeline,"event_count":len(events)}
