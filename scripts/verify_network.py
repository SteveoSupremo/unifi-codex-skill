#!/usr/bin/env python3
import argparse, json, socket, ssl, urllib.request
def tcp(host,port,timeout):
    try:
        with socket.create_connection((host,port),timeout): return True
    except OSError:return False
def main():
    p=argparse.ArgumentParser(); p.add_argument("--host",required=True); p.add_argument("--dns-name",default="example.com"); p.add_argument("--timeout",type=float,default=3); a=p.parse_args()
    results={"controller_tcp_443":tcp(a.host,443,a.timeout)}
    try: socket.getaddrinfo(a.dns_name,443); results["dns_resolution"]=True
    except OSError: results["dns_resolution"]=False
    results["note"]="TCP/service checks do not rely on ICMP"
    print(json.dumps(results,indent=2)); raise SystemExit(0 if all(v for k,v in results.items() if k!="note") else 2)
if __name__=="__main__":main()
