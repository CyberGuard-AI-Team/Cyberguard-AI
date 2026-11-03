"""Host event Isolation Forest. Train explicitly on collected host telemetry; no pretrained claims."""
import argparse, json
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

VERSION = "host-iforest-v1"
NUMERIC = ("event_id_num", "hour_utc", "weekday_utc", "user_event_count_1h", "source_event_count_1h", "is_failure", "is_privilege", "is_process", "is_service")
def features(record):
    from datetime import datetime
    try: dt=datetime.fromisoformat(record["timestamp"].replace("Z","+00:00"))
    except (KeyError,ValueError): dt=datetime.fromtimestamp(0)
    try: eid=float(record.get("eventId", "0"))
    except (TypeError,ValueError): eid=0.0
    typ=str(record.get("eventType", "")).lower(); status=str(record.get("status", "")).lower()
    raw=[eid,dt.hour,dt.weekday(),record.get("user_event_count_1h",0),record.get("source_event_count_1h",0),int("fail" in typ or status=="failed"),int("privilege" in typ or "sudo" in typ),int("process" in typ),int("service" in typ)]
    return np.nan_to_num(np.asarray(raw,dtype=float),nan=0,posinf=0,neginf=0)
def train(input_path, model_path, contamination):
    rows=[json.loads(line) for line in Path(input_path).read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows)<50: raise ValueError("At least 50 host event records are required for a minimally useful baseline.")
    x=np.vstack([features(r) for r in rows]); scaler=StandardScaler().fit(x); normalized=scaler.transform(x)
    model=IsolationForest(n_estimators=200,contamination=contamination,random_state=42).fit(normalized)
    scores=-model.score_samples(normalized)
    artifact={"version":VERSION,"model":model,"scaler":scaler,"feature_names":list(NUMERIC),"training_rows":len(rows),"training_score_p50":float(np.quantile(scores,.5)),"training_score_p95":float(np.quantile(scores,.95))}
    joblib.dump(artifact,model_path); return {k:v for k,v in artifact.items() if k not in ("model","scaler","feature_names")}
def predict(row, model_path):
    artifact=joblib.load(model_path); x=artifact["scaler"].transform(features(row).reshape(1,-1))
    score=float(-artifact["model"].score_samples(x)[0]); threshold=float(artifact["training_score_p95"])
    return {"modelVersion":artifact["version"],"anomalyScore":round(min(1.0,score/max(threshold,1e-9)),6),"isAnomaly":bool(score>threshold),"trainingRows":artifact["training_rows"]}
def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
    t=sub.add_parser("train"); t.add_argument("input"); t.add_argument("model"); t.add_argument("--contamination",type=float,default=.03)
    i=sub.add_parser("predict"); i.add_argument("input"); i.add_argument("model")
    a=p.parse_args()
    if a.cmd=="train": print(json.dumps(train(a.input,a.model,a.contamination),indent=2))
    else: print(json.dumps(predict(json.loads(Path(a.input).read_text(encoding="utf-8")),a.model),indent=2))
if __name__=="__main__": main()
