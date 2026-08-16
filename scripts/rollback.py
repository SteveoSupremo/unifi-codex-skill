#!/usr/bin/env python3
"""Rollback planner. Version 1 never submits a request."""
import argparse, json
from pathlib import Path
from unifi_common import json_diff
def main():
    p=argparse.ArgumentParser(); p.add_argument("snapshot",type=Path); p.add_argument("--current",type=Path,required=True); p.add_argument("--dry-run",action="store_true",default=True); a=p.parse_args()
    snap=json.loads(a.snapshot.read_text()); cur=json.loads(a.current.read_text())
    print("ROLLBACK PLAN ONLY — live restore is unsupported in version 1")
    print(json_diff(cur,snap) or "No differences.")
if __name__=="__main__": main()
