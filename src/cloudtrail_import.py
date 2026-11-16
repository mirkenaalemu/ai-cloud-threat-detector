"""Read-only CloudTrail JSON importer for authorized offline exports.

Accepts AWS CloudTrail Records JSON or a single CloudTrail record. Does not
connect to AWS, access credentials, or perform any cloud action.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from src.pipeline import extract_features

MAX_BYTES=5_000_000
MAX_RECORDS=20_000
ALLOWED_EVENTS={"ConsoleLogin","AttachUserPolicy","PutUserPolicy",
                "CreateAccessKey","DeleteTrail","StopLogging",
                "ListBuckets","GetObject","DescribeInstances"}

def parse_cloudtrail(payload):
    if isinstance(payload,(str,bytes)):
        if len(payload)>MAX_BYTES:
            raise ValueError("Input exceeds size limit")
        payload=json.loads(payload)
    if not isinstance(payload,dict):
        raise ValueError("Expected a CloudTrail JSON object")
    records=payload.get("Records",[payload])
    if not isinstance(records,list) or len(records)>MAX_RECORDS:
        raise ValueError("Invalid record list or too many records")
    events=[]
    for index,rec in enumerate(records):
        if not isinstance(rec,dict):
            continue
        name=rec.get("eventName")
        if name not in ALLOWED_EVENTS:
            continue
        when=rec.get("eventTime")
        if not isinstance(when,str):
            continue
        try:
            dt=datetime.fromisoformat(when.replace("Z","+00:00"))
        except ValueError:
            continue
        if dt.tzinfo is None:
            continue
        identity=rec.get("userIdentity") or {}
        if not isinstance(identity,dict):
            identity={}
        principal=str(identity.get("principalId") or identity.get("arn") or "unknown")[:180]
        source=str(rec.get("sourceIPAddress") or "unknown")[:90]
        error=rec.get("errorCode")
        events.append({"event_id":str(rec.get("eventID") or f"import-{index}")[:128],
                       "time":dt.astimezone(timezone.utc).isoformat(),
                       "principal":principal,"source_ip":source,
                       "action":"AttachUserPolicy" if name in ("PutUserPolicy","CreateAccessKey","DeleteTrail","StopLogging") else name,
                       "success":not bool(error),
                       # Only an internal adapter default; never treat as ground truth.
                       "label":0})
    return events

def extract_unlabeled_windows(payload):
    events=parse_cloudtrail(payload)
    if not events:
        return []
    rows=extract_features(events)
    # Remove evaluation-only fields; no accuracy metric is available without labels.
    return [{k:v for k,v in row.items() if k!="label"} for row in rows]

def load_export(path):
    p=Path(path)
    if p.stat().st_size>MAX_BYTES:
        raise ValueError("Export exceeds size limit")
    return extract_unlabeled_windows(p.read_text(encoding="utf-8"))

if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser(description="Analyze authorized local CloudTrail JSON exports")
    parser.add_argument("path",help="Local path to exported CloudTrail JSON")
    args=parser.parse_args()
    print(json.dumps(load_export(args.path),indent=2))
