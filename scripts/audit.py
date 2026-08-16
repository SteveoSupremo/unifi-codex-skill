#!/usr/bin/env python3
"""Read-only, evidence-oriented UniFi audit engine."""
import argparse, datetime as dt, json, sys
from pathlib import Path
from unifi_common import Finding, ROOT, redact

SEVERITY_ORDER={"critical":0,"high":1,"medium":2,"low":3,"informational":4}
def analyze(data, scope):
 f=[]; pfs=data.get("port_forwards") or []
 if scope in ("all","exposure","firewall"):
  for x in pfs:
   if x.get("enabled",True): f.append(Finding("high","WAN exposure",f"Enabled port forward: {x.get('name','unnamed')}",f"destination={x.get('fwd','unknown')} port={x.get('dst_port',x.get('fwd_port','unknown'))}","Creates an inbound path from WAN.","high","Confirm purpose, source scope, and owner.","reported",False))
  for r in (data.get("firewall_rules") or [])+(data.get("traffic_rules") or []):
   text=json.dumps(r).lower()
   if r.get("enabled",True) and r.get("action","accept").lower() in ("accept","allow") and ("any" in text or not r.get("src_networkconf_id")):
    f.append(Finding("medium","Firewall rule quality",f"Broad allow candidate: {r.get('name','unnamed')}","Rule appears broad from available fields.","Broad scope can weaken segmentation.","low","Review complete source/destination semantics; do not delete automatically.","inferred",False))
 if scope in ("all","network"):
  expected={1:"192.168.1.0/24",2:"192.168.2.0/24",3:"192.168.3.0/24",4:"192.168.6.0/24",5:"192.168.7.0/24",99:"192.168.99.0/24"}
  seen={int(n.get("vlan",n.get("vlan_id",1))):n.get("ip_subnet",n.get("subnet")) for n in data.get("networks",[]) if str(n.get("vlan",n.get("vlan_id",1))).isdigit()}
  for vlan,subnet in expected.items():
   if vlan not in seen: f.append(Finding("medium","Desired-state drift",f"VLAN {vlan} not observed",f"Expected {subnet}","The configured topology may differ or the API may not expose it.","medium","Verify controller/site and network inventory.","reported",False))
 if scope in ("all","performance","wifi","health"):
  if not data.get("status"): f.append(Finding("informational","Telemetry","Health telemetry unavailable","No status data supplied.","Performance cannot be assessed without evidence.","high","Collect read-only health/device statistics.","not_available",False))
 return sorted(f,key=lambda x:SEVERITY_ORDER[x.severity])
def markdown(scope,findings):
 lines=[f"# UniFi {scope.title()} Audit","",f"Generated: {dt.datetime.now(dt.timezone.utc).isoformat()}","","## Executive Summary","",f"{len(findings)} finding(s). No changes were made.",""]
 for sev in ("critical","high","medium","low","informational"):
  group=[x for x in findings if x.severity==sev]
  if group:
   lines += [f"## {sev.title()}",""]
   for x in group: lines += [f"### {x.title}","",f"- Category: {x.category}",f"- Evidence ({x.evidence_type}): {x.evidence}",f"- Why it matters: {x.why}",f"- Confidence: {x.confidence}",f"- Recommendation: {x.recommendation}",f"- Safe to automate: {'yes' if x.safe_to_automate else 'no'}",""]
 lines += ["## Items Requiring Human Decision","","All configuration recommendations require human review and separate authorization.",""]
 return "\n".join(lines)
def main():
 p=argparse.ArgumentParser(); p.add_argument("scope",choices=["network","firewall","exposure","performance","wifi","health","all"]); p.add_argument("--input",type=Path); p.add_argument("--report",action="store_true"); a=p.parse_args()
 if not a.input: raise SystemExit("Version 1 audit requires --input SANITIZED_INVENTORY.json; collect with inventory.py")
 findings=analyze(json.loads(a.input.read_text()),a.scope); out=markdown(a.scope,findings)
 if a.report:
  ROOT.joinpath("reports").mkdir(exist_ok=True); path=ROOT/"reports"/f"{dt.date.today().isoformat()}-{a.scope}-audit.md"; path.write_text(out); print(path)
 else: print(out)
if __name__=="__main__":main()
