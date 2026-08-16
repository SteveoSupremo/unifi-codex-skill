#!/usr/bin/env python3
"""Sanitized read-only inventory collector."""
import argparse, json, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from unifi_common import load_env, redact

READ_PLAN=[
 ("GET","/proxy/network/integration/v1/sites"),
 ("GET","/proxy/network/api/s/{site}/stat/health"),
 ("GET","/proxy/network/api/s/{site}/rest/networkconf"),
 ("GET","/proxy/network/api/s/{site}/stat/device"),
 ("GET","/proxy/network/api/s/{site}/rest/firewallrule"),
 ("GET","/proxy/network/api/s/{site}/rest/portforward"),
 ("GET","/proxy/network/v2/api/site/{site}/trafficrules"),
]
def main():
 p=argparse.ArgumentParser(); p.add_argument("--plan",action="store_true"); p.add_argument("--output",type=Path); a=p.parse_args()
 env=load_env(); plan=[{"method":m,"endpoint":e.format(site=env.get("UNIFI_SITE") or "default")} for m,e in READ_PLAN]
 if a.plan:
  print(json.dumps({"mode":"READ_ONLY","requests":plan},indent=2)); return
 if not env.get("UDM_HOST") or not env.get("UNIFI_API_KEY"): raise SystemExit("UDM_HOST and UNIFI_API_KEY are required; use --plan without credentials")
 from udm import UDMClient
 c=UDMClient(env["UDM_HOST"],env["UNIFI_API_KEY"]); data={"status":c.status(),"networks":c.networks(),"devices":c.devices(),"firewall_rules":c.firewall_rules(),"traffic_rules":c.traffic_rules(),"port_forwards":c.portforward_rules()}
 safe=redact(data); text=json.dumps(safe,indent=2,sort_keys=True)
 if a.output: a.output.write_text(text+"\n")
 else: print(text)
if __name__=="__main__":main()
