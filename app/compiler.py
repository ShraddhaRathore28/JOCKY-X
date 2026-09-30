COLLECTORS={"process","network","file","memory","driver","system"}
DETECTIONS={"process_anomaly","beaconing","dns_tunneling","file_anomaly","memory_anomaly","driver_anomaly","lateral_movement","data_exfiltration"}

def csv(v):
    return [x.strip().lower() for x in v.split(",") if x.strip()]

def compile_jocky(source):
    lines=[x.strip() for x in source.splitlines() if x.strip() and not x.strip().startswith("#")]
    if not lines or not lines[0].upper().startswith("INVESTIGATION "):
        raise ValueError("First statement must be: INVESTIGATION <name>")
    ir={"ir_version":"1.0","language":"JOCKY","investigation":lines[0].split(None,1)[1],
        "targets":["windows","ubuntu"],"collect":["process","network","file"],"detect":[],
        "timeline":True,"explain":True}
    for line in lines[1:]:
        key,_,value=line.partition(" "); key=key.upper(); value=value.strip()
        if key=="TARGET":
            v=csv(value)
            if not v or not set(v)<= {"windows","ubuntu"}: raise ValueError("TARGET must use windows and/or ubuntu")
            ir["targets"]=v
        elif key=="COLLECT":
            v=csv(value); bad=set(v)-COLLECTORS
            if bad: raise ValueError(f"Unsupported collector(s): {sorted(bad)}")
            ir["collect"]=v
        elif key=="DETECT":
            v=csv(value); bad=set(v)-DETECTIONS
            if bad: raise ValueError(f"Unsupported detection(s): {sorted(bad)}")
            ir["detect"]=v
        elif key in ("TIMELINE","EXPLAIN"):
            ir[key.lower()]=value.lower()=="true"
        else: raise ValueError(f"Unknown JOCKY statement: {key}")
    return ir

def pretty_ir(ir):
    return "\n".join([f"JOCKY-IR {ir['ir_version']}",f"investigation={ir['investigation']}",
        f"targets={','.join(ir['targets'])}",f"collect={','.join(ir['collect'])}",
        f"detect={','.join(ir['detect'])}",f"timeline={ir['timeline']}",f"explain={ir['explain']}"])
