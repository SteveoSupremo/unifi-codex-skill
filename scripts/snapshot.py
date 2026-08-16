#!/usr/bin/env python3
import argparse, datetime as dt, json
from pathlib import Path
from unifi_common import ROOT, redact

def create_snapshot(target, object_type, object_id, current, reason, intended=None, base=None):
    stamp=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    folder=(base or ROOT/"snapshots")/stamp; folder.mkdir(parents=True, exist_ok=False)
    safe_id="".join(c if c.isalnum() or c in "-_" else "_" for c in object_id)
    name=f"{object_type}-{safe_id}.json"; payload=redact(current)
    (folder/name).write_text(json.dumps(payload, indent=2, sort_keys=True)+"\n")
    manifest={"timestamp":stamp,"target":target,"object_id":object_id,"object_type":object_type,
      "reason":reason,"intended_change":redact(intended),"files":[name]}
    (folder/"manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
    return folder

def main():
    p=argparse.ArgumentParser(); p.add_argument("--target",required=True); p.add_argument("--type",required=True)
    p.add_argument("--id",required=True); p.add_argument("--input",required=True,type=Path); p.add_argument("--reason",required=True); a=p.parse_args()
    print(create_snapshot(a.target,a.type,a.id,json.loads(a.input.read_text()),a.reason))
if __name__=="__main__": main()
