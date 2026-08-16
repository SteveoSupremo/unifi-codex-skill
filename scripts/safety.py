#!/usr/bin/env python3
import argparse, json
from unifi_common import load_env, writes_enabled

def main():
    p=argparse.ArgumentParser(); p.add_argument("command", choices=["status"]); a=p.parse_args()
    env=load_env()
    print(json.dumps({"mode":"LIVE_WRITES_ENABLED" if writes_enabled(env) else "READ_ONLY",
      "host_configured":bool(env.get("UDM_HOST")), "api_key_configured":bool(env.get("UNIFI_API_KEY")),
      "live_mutation":writes_enabled(env)}, indent=2))
if __name__ == "__main__": main()
