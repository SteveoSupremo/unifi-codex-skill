#!/usr/bin/env python3
"""
UniFi Dream Machine Pro API helper script.

Configuration is read from a `.env` file at the project root (see `.env.example`)
or from environment variables. Real environment variables take precedence over
the .env file. Supported keys:
  UDM_HOST         UniFi controller hostname (default: unifi.local)
  UNIFI_API_KEY    API key; if unset, falls back to `pass internal/unifi/api-key`

Usage: python udm.py <command> [subcommand] [args] [--json]

Global flags:
  --json       Output raw JSON (default: pretty-printed)
  --host HOST  Override host (default: $UDM_HOST or unifi.local)
"""

import argparse
import json
import os
import subprocess
import sys
import time
import warnings
from pathlib import Path
from typing import Any

import urllib.request
import urllib.error
import ssl

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


class UDMReadError(RuntimeError):
    """Sanitized transport error for reads and guarded writes."""

    def __init__(self, status: int | None, reason: str, *,
                 error_kind: str = "unknown", response_shape: str | None = None,
                 response_body: Any = None, content_type: str | None = None):
        super().__init__(reason)
        self.status = status
        self.error_kind = error_kind
        self.response_shape = response_shape
        self.response_body = response_body
        self.content_type = content_type


def _json_shape(value: Any) -> str:
    if value is None:
        return "empty"
    if isinstance(value, dict):
        return "object:" + ",".join(sorted(str(key) for key in value))
    if isinstance(value, list):
        return "array"
    return type(value).__name__


def _sanitize_error_body(value: Any) -> Any:
    """Retain useful validation errors while removing authentication-like fields."""
    blocked = ("authorization", "cookie", "csrf", "password", "secret", "token", "api_key", "apikey")
    if isinstance(value, dict):
        return {key: ("<redacted>" if any(marker in str(key).lower() for marker in blocked)
                      else _sanitize_error_body(child)) for key, child in value.items()}
    if isinstance(value, list):
        return [_sanitize_error_body(child) for child in value]
    return value


def _load_dotenv() -> None:
    """Load KEY=VALUE pairs from .env at the project root, if present.

    Existing environment variables are never overwritten — real env wins over file.
    """
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.is_file():
        return
    for raw in env_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


_load_dotenv()

DEFAULT_HOST = os.environ.get("UDM_HOST", "unifi.local")
DEFAULT_SITE = "default"


def get_api_key() -> str:
    env_key = os.environ.get("UNIFI_API_KEY")
    if env_key:
        return env_key
    result = subprocess.run(
        ["pass", "internal/unifi/api-key"],
        capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


class UDMClient:
    def __init__(self, host: str, api_key: str):
        self.base = f"https://{host}"
        self.site = DEFAULT_SITE
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _legacy(self, path: str) -> str:
        return f"{self.base}/proxy/network/api/s/{self.site}/{path}"

    def _v2(self, path: str) -> str:
        return f"{self.base}/proxy/network/v2/api/site/{self.site}/{path}"

    def _integration(self, path: str) -> str:
        return f"{self.base}/proxy/network/integration/v1/{path}"

    def _request(self, method: str, url: str, body: dict | None = None,
                 unwrap: bool = True, fatal: bool = True) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self.headers, method=method)
        try:
            with urllib.request.urlopen(req, context=self.ctx) as resp:
                raw = resp.read().decode()
                if not raw:
                    return {}
                parsed = json.loads(raw)
                # Unwrap legacy API envelope
                if unwrap and isinstance(parsed, dict) and "data" in parsed:
                    return parsed["data"]
                return parsed
        except urllib.error.HTTPError as e:
            if not fatal:
                raise UDMReadError(e.code, f"HTTP {e.code}") from e
            body_text = e.read().decode()
            print(f"HTTP {e.code}: {body_text}", file=sys.stderr)
            sys.exit(1)
        except urllib.error.URLError as e:
            if not fatal:
                raise UDMReadError(None, "transport unavailable", error_kind="transport") from e
            raise

    def get(self, url: str) -> Any:
        return self._request("GET", url)

    def get_optional(self, url: str, *, unwrap: bool = True) -> Any:
        """GET without terminating the process or printing controller error bodies."""
        return self._request("GET", url, unwrap=unwrap, fatal=False)

    def post(self, url: str, body: dict) -> Any:
        return self._request("POST", url, body)

    def put(self, url: str, body: dict) -> Any:
        return self._request("PUT", url, body)

    def delete(self, url: str) -> Any:
        return self._request("DELETE", url)

    def guarded_write(self, method: str, url: str, body: dict | None = None) -> Any:
        """Sanitized transport used only after the external mutation gate approves."""
        method = method.upper()
        if method not in {"POST", "PUT", "DELETE"}:
            raise ValueError("guarded_write only accepts mutation methods")
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, headers=self.headers, method=method)
        try:
            with urllib.request.urlopen(request, context=self.ctx) as response:
                raw = response.read().decode()
                parsed = json.loads(raw) if raw else None
                return {"_guarded_write_response": True, "status": response.status,
                        "body": parsed, "body_shape": _json_shape(parsed)}
        except urllib.error.HTTPError as error:
            raw = error.read().decode()
            try:
                parsed = json.loads(raw) if raw else None
            except (ValueError, TypeError):
                parsed = "non-json"
            safe_body = _sanitize_error_body(parsed)
            raise UDMReadError(error.code, f"HTTP {error.code}", error_kind="http",
                               response_shape=_json_shape(parsed), response_body=safe_body,
                               content_type=error.headers.get_content_type() if error.headers else None) from error
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            kind = "timeout" if isinstance(error, TimeoutError) else "transport"
            raise UDMReadError(None, "transport unavailable", error_kind=kind) from error

    # ── Status / Health ──────────────────────────────────────────────────────

    def status(self) -> Any:
        health = self.get(self._legacy("stat/health"))
        sysinfo = self.get(self._legacy("stat/sysinfo"))
        return {"health": health, "sysinfo": sysinfo[0] if sysinfo else sysinfo}

    # ── Clients ──────────────────────────────────────────────────────────────

    def clients_active(self) -> Any:
        return self.get(self._legacy("stat/sta"))

    def clients_all(self) -> Any:
        return self.get(self._legacy("stat/alluser"))

    def clients_action(self, cmd: str, mac: str) -> Any:
        return self.post(self._legacy("cmd/stamgr"), {"cmd": cmd, "mac": mac})

    # ── Devices ──────────────────────────────────────────────────────────────

    def devices(self) -> Any:
        return self.get(self._legacy("stat/device"))

    def device_action(self, cmd: str, mac: str) -> Any:
        return self.post(self._legacy("cmd/devmgr"), {"cmd": cmd, "mac": mac})

    def device_update(self, device_id: str, body: dict) -> Any:
        return self.put(self._legacy(f"rest/device/{device_id}"), body)

    # ── Networks / VLANs ─────────────────────────────────────────────────────

    def networks(self) -> Any:
        return self.get(self._legacy("rest/networkconf"))

    def network_update(self, network_id: str, body: dict) -> Any:
        return self.put(self._legacy(f"rest/networkconf/{network_id}"), body)

    def vlans(self) -> Any:
        sites = self.get(self._integration("sites"))
        if not sites:
            return []
        site_id = sites[0].get("id", self.site) if isinstance(sites, list) else self.site
        # Integration API renamed vlans -> networks
        return self.get(self._integration(f"sites/{site_id}/networks"))

    def wlans(self) -> Any:
        return self.get(self._legacy("rest/wlanconf"))

    def wlan_update(self, wlan_id: str, body: dict) -> Any:
        return self.put(self._legacy(f"rest/wlanconf/{wlan_id}"), body)

    # ── Firewall Rules ────────────────────────────────────────────────────────

    def firewall_rules(self) -> Any:
        return self.get(self._legacy("rest/firewallrule"))

    def firewall_create(self, rule: dict) -> Any:
        return self.post(self._legacy("rest/firewallrule"), rule)

    def firewall_update(self, rule_id: str, rule: dict) -> Any:
        return self.put(self._legacy(f"rest/firewallrule/{rule_id}"), rule)

    def firewall_delete(self, rule_id: str) -> Any:
        return self.delete(self._legacy(f"rest/firewallrule/{rule_id}"))

    def firewall_groups(self) -> Any:
        return self.get(self._legacy("rest/firewallgroup"))

    def firewall_group_create(self, group: dict) -> Any:
        return self.post(self._legacy("rest/firewallgroup"), group)

    def firewall_group_update(self, group_id: str, group: dict) -> Any:
        return self.put(self._legacy(f"rest/firewallgroup/{group_id}"), group)

    def firewall_group_delete(self, group_id: str) -> Any:
        return self.delete(self._legacy(f"rest/firewallgroup/{group_id}"))

    # ── Traffic Rules (v2) ────────────────────────────────────────────────────

    def traffic_rules(self) -> Any:
        return self.get(self._v2("trafficrules"))

    def traffic_rule_create(self, rule: dict) -> Any:
        return self.post(self._v2("trafficrules"), rule)

    def traffic_rule_update(self, rule_id: str, rule: dict) -> Any:
        return self.put(self._v2(f"trafficrules/{rule_id}"), rule)

    def traffic_rule_toggle(self, rule_id: str, enabled: bool) -> Any:
        rules = self.traffic_rules()
        rule = next((r for r in rules if r.get("_id") == rule_id or r.get("id") == rule_id), None)
        if not rule:
            print(f"Traffic rule {rule_id} not found", file=sys.stderr)
            sys.exit(1)
        rule["enabled"] = enabled
        return self.traffic_rule_update(rule_id, rule)

    def traffic_rule_delete(self, rule_id: str) -> Any:
        return self.delete(self._v2(f"trafficrules/{rule_id}"))

    # ── Port Forwarding ───────────────────────────────────────────────────────

    def portforward_rules(self) -> Any:
        return self.get(self._legacy("rest/portforward"))

    def portforward_create(self, rule: dict) -> Any:
        return self.post(self._legacy("rest/portforward"), rule)

    def portforward_update(self, rule_id: str, rule: dict) -> Any:
        return self.put(self._legacy(f"rest/portforward/{rule_id}"), rule)

    def portforward_toggle(self, rule_id: str, enabled: bool) -> Any:
        rules = self.portforward_rules()
        rule = next((r for r in rules if r.get("_id") == rule_id), None)
        if not rule:
            print(f"Port forward rule {rule_id} not found", file=sys.stderr)
            sys.exit(1)
        rule["enabled"] = enabled
        return self.portforward_update(rule_id, rule)

    def portforward_delete(self, rule_id: str) -> Any:
        return self.delete(self._legacy(f"rest/portforward/{rule_id}"))

    # ── VPN ───────────────────────────────────────────────────────────────────

    def vpn_status(self) -> Any:
        # Network 10.x removed rest/vpnclient, rest/vpnserver and stat/vpn;
        # the v2 VPN API replaces them.
        return {
            "connections": self.get(self._v2("vpn/connections")).get("connections", []),
            "client_connections": self.get(self._v2("vpn/client-connections")).get("connections", []),
            "users": self.get(self._v2("vpn/users")),
        }

    # ── Events & Alarms ───────────────────────────────────────────────────────
    # Network Application 10.x removed the legacy stat/event and stat/alarm
    # endpoints. Events and critical alerts now live behind the v2 system-log
    # API (POST-based, paginated, timestamps in epoch milliseconds).

    def events(self, hours: int = 24) -> Any:
        cutoff = int(time.time() * 1000) - hours * 3600 * 1000
        results: list = []
        page = 0
        while True:
            resp = self._request("POST", self._v2("system-log/all"),
                                 {"pageNumber": page, "pageSize": 100}, unwrap=False)
            batch = resp.get("data", []) if isinstance(resp, dict) else []
            if not batch:
                break
            results.extend(e for e in batch if e.get("timestamp", 0) >= cutoff)
            if (batch[-1].get("timestamp", 0) < cutoff
                    or page + 1 >= resp.get("total_page_count", 0)):
                break
            page += 1
        return results

    def alarms(self) -> Any:
        """Unread critical alerts — the Network 10.x successor to alarms."""
        return self.post(self._v2("system-log/critical"), {})

    def alarms_archive_all(self) -> Any:
        return self._request("PUT", self._v2("system-log/critical/mark-all-as-read"), {})

    def alarm_archive(self, alarm_id: str) -> Any:
        return self._request("PUT", self._v2(f"system-log/critical/{alarm_id}/mark-as-read"), {})

    # ── Stats / DPI ───────────────────────────────────────────────────────────

    def stats_dpi(self) -> Any:
        return self.get(self._legacy("stat/dpi"))

    def stats_gateway(self) -> Any:
        # Network 10.x removed stat/gateway; the WAN/www health subsystems carry
        # the same information (WAN IP, throughput, speedtest, latency, uptime).
        health = self.get(self._legacy("stat/health"))
        return {s["subsystem"]: s for s in health
                if s.get("subsystem") in ("wan", "www")}

    def stats_report(self, interval: str = "hourly", attrs: list[str] | None = None,
                     start: int | None = None, end: int | None = None) -> Any:
        body: dict = {"attrs": attrs or ["bytes", "wan-tx_bytes", "wan-rx_bytes", "duration"]}
        if start:
            body["start"] = start
        if end:
            body["end"] = end
        return self.post(self._legacy(f"stat/report/{interval}.site"), body)

    # ── Routes ────────────────────────────────────────────────────────────────

    def routes(self) -> Any:
        return self.get(self._legacy("rest/routing"))

    # ── Dynamic DNS ───────────────────────────────────────────────────────────

    def ddns(self) -> Any:
        return self.get(self._legacy("rest/dynamicdns"))

    # ── Raw ───────────────────────────────────────────────────────────────────

    def raw(self, method: str, path: str, body: dict | None = None) -> Any:
        if path.startswith("http"):
            url = path
        elif path.startswith("/"):
            url = f"{self.base}{path}"
        else:
            url = f"{self.base}/{path}"
        return self._request(method.upper(), url, body)


def output(data: Any, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(data))
    else:
        print(json.dumps(data, indent=2))


def main() -> None:
    # Strip --json / --host before argparse so they work in any position
    argv = sys.argv[1:]
    as_json = "--json" in argv
    if as_json:
        argv.remove("--json")

    override_host = DEFAULT_HOST
    if "--host" in argv:
        idx = argv.index("--host")
        override_host = argv[idx + 1]
        argv = argv[:idx] + argv[idx + 2:]

    parser = argparse.ArgumentParser(
        description="UniFi Dream Machine Pro CLI helper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # status
    sub.add_parser("status", help="System health and info")

    # clients
    p_cli = sub.add_parser("clients", help="Manage clients")
    p_cli.add_argument("action", nargs="?", choices=["block", "unblock", "kick"],
                       help="Action to perform")
    p_cli.add_argument("mac", nargs="?", help="MAC address")
    p_cli.add_argument("--all", action="store_true", help="Include offline clients")

    # devices
    p_dev = sub.add_parser("devices", help="Manage network devices")
    p_dev.add_argument("action", nargs="?",
                       choices=["restart", "upgrade", "adopt", "force-provision", "spectrum-scan"],
                       help="Action to perform")
    p_dev.add_argument("mac", nargs="?", help="MAC address")

    # networks
    p_net = sub.add_parser("networks", help="List or update network configs")
    p_net.add_argument("action", nargs="?", choices=["update"], help="Action")
    p_net.add_argument("id", nargs="?", help="Network ID")
    p_net.add_argument("--data", help="JSON body for update")

    # vlans
    sub.add_parser("vlans", help="List VLANs")

    # wlans
    p_wlan = sub.add_parser("wlans", help="List or update wireless networks")
    p_wlan.add_argument("action", nargs="?", choices=["update"], help="Action")
    p_wlan.add_argument("id", nargs="?", help="WLAN ID")
    p_wlan.add_argument("--data", help="JSON body for update")

    # firewall
    p_fw = sub.add_parser("firewall", help="Manage firewall rules and groups")
    p_fw.add_argument("action", choices=["list", "create", "update", "delete",
                                          "groups", "group-create", "group-update", "group-delete"])
    p_fw.add_argument("id", nargs="?", help="Rule/group ID")
    p_fw.add_argument("--data", help="JSON body (for create/update)")

    # trafficrules
    p_tr = sub.add_parser("trafficrules", help="Manage v2 traffic rules")
    p_tr.add_argument("action", choices=["list", "create", "update", "delete",
                                          "enable", "disable"])
    p_tr.add_argument("id", nargs="?", help="Rule ID")
    p_tr.add_argument("--data", help="JSON body (for create/update)")

    # portforward
    p_pf = sub.add_parser("portforward", help="Manage port forwarding rules")
    p_pf.add_argument("action", choices=["list", "create", "update", "delete",
                                          "enable", "disable"])
    p_pf.add_argument("id", nargs="?", help="Rule ID")
    p_pf.add_argument("--data", help="JSON body (for create/update)")

    # vpn
    sub.add_parser("vpn", help="VPN status")

    # events
    p_ev = sub.add_parser("events", help="Recent events")
    p_ev.add_argument("--hours", type=int, default=24, help="How many hours back (default: 24)")

    # alarms
    p_al = sub.add_parser("alarms", help="Alarms / alerts")
    p_al.add_argument("action", nargs="?", choices=["archive-all", "archive"],
                      help="Action")
    p_al.add_argument("id", nargs="?", help="Alarm ID (for archive)")

    # stats
    p_st = sub.add_parser("stats", help="Traffic stats and DPI")
    p_st.add_argument("type", nargs="?", choices=["dpi", "gateway", "report"],
                      default="gateway", help="Stat type (default: gateway)")
    p_st.add_argument("--interval", choices=["5minutes", "hourly", "daily"],
                      default="hourly", help="Report interval")

    # routes
    sub.add_parser("routes", help="Static routes")

    # ddns
    sub.add_parser("ddns", help="Dynamic DNS configs")

    # raw
    p_raw = sub.add_parser("raw", help="Raw API call")
    p_raw.add_argument("method", help="HTTP method (GET, POST, PUT, DELETE)")
    p_raw.add_argument("path", help="URL path or full URL")
    p_raw.add_argument("--data", help="JSON body")

    args = parser.parse_args(argv)

    # HomeLab safety boundary: retain upstream command parsing and client methods
    # for useful diffs, but never expose an unguarded mutation through this CLI.
    unguarded_write = (
        (args.cmd in {"clients", "devices"} and bool(getattr(args, "action", None))) or
        (args.cmd in {"networks", "wlans"} and getattr(args, "action", None) == "update") or
        (args.cmd == "firewall" and getattr(args, "action", None) not in {"list", "groups"}) or
        (args.cmd in {"trafficrules", "portforward"} and getattr(args, "action", None) != "list") or
        (args.cmd == "alarms" and bool(getattr(args, "action", None))) or
        (args.cmd == "raw" and str(getattr(args, "method", "GET")).upper() != "GET")
    )
    if unguarded_write:
        parser.error("unguarded low-level writes are disabled; use scripts/mutate.py with --plan and an exact approval token")

    api_key = get_api_key()
    client = UDMClient(override_host, api_key)

    if args.cmd == "status":
        output(client.status(), as_json)

    elif args.cmd == "clients":
        if args.action:
            if not args.mac:
                parser.error(f"MAC address required for {args.action}")
            cmd_map = {"block": "block-sta", "unblock": "unblock-sta", "kick": "kick-sta"}
            output(client.clients_action(cmd_map[args.action], args.mac), as_json)
        elif args.all:
            output(client.clients_all(), as_json)
        else:
            output(client.clients_active(), as_json)

    elif args.cmd == "devices":
        if args.action:
            if not args.mac:
                parser.error(f"MAC address required for {args.action}")
            output(client.device_action(args.action, args.mac), as_json)
        else:
            output(client.devices(), as_json)

    elif args.cmd == "networks":
        if args.action == "update":
            if not args.id or not args.data:
                parser.error("networks update requires --id and --data")
            output(client.network_update(args.id, json.loads(args.data)), as_json)
        else:
            output(client.networks(), as_json)

    elif args.cmd == "vlans":
        output(client.vlans(), as_json)

    elif args.cmd == "wlans":
        if args.action == "update":
            if not args.id or not args.data:
                parser.error("wlans update requires id and --data")
            output(client.wlan_update(args.id, json.loads(args.data)), as_json)
        else:
            output(client.wlans(), as_json)

    elif args.cmd == "firewall":
        a = args.action
        if a == "list":
            output(client.firewall_rules(), as_json)
        elif a == "create":
            if not args.data:
                parser.error("firewall create requires --data")
            output(client.firewall_create(json.loads(args.data)), as_json)
        elif a == "update":
            if not args.id or not args.data:
                parser.error("firewall update requires id and --data")
            output(client.firewall_update(args.id, json.loads(args.data)), as_json)
        elif a == "delete":
            if not args.id:
                parser.error("firewall delete requires id")
            output(client.firewall_delete(args.id), as_json)
        elif a == "groups":
            output(client.firewall_groups(), as_json)
        elif a == "group-create":
            if not args.data:
                parser.error("firewall group-create requires --data")
            output(client.firewall_group_create(json.loads(args.data)), as_json)
        elif a == "group-update":
            if not args.id or not args.data:
                parser.error("firewall group-update requires id and --data")
            output(client.firewall_group_update(args.id, json.loads(args.data)), as_json)
        elif a == "group-delete":
            if not args.id:
                parser.error("firewall group-delete requires id")
            output(client.firewall_group_delete(args.id), as_json)

    elif args.cmd == "trafficrules":
        a = args.action
        if a == "list":
            output(client.traffic_rules(), as_json)
        elif a == "create":
            if not args.data:
                parser.error("trafficrules create requires --data")
            output(client.traffic_rule_create(json.loads(args.data)), as_json)
        elif a == "update":
            if not args.id or not args.data:
                parser.error("trafficrules update requires id and --data")
            output(client.traffic_rule_update(args.id, json.loads(args.data)), as_json)
        elif a == "enable":
            if not args.id:
                parser.error("trafficrules enable requires id")
            output(client.traffic_rule_toggle(args.id, True), as_json)
        elif a == "disable":
            if not args.id:
                parser.error("trafficrules disable requires id")
            output(client.traffic_rule_toggle(args.id, False), as_json)
        elif a == "delete":
            if not args.id:
                parser.error("trafficrules delete requires id")
            output(client.traffic_rule_delete(args.id), as_json)

    elif args.cmd == "portforward":
        a = args.action
        if a == "list":
            output(client.portforward_rules(), as_json)
        elif a == "create":
            if not args.data:
                parser.error("portforward create requires --data")
            output(client.portforward_create(json.loads(args.data)), as_json)
        elif a == "update":
            if not args.id or not args.data:
                parser.error("portforward update requires id and --data")
            output(client.portforward_update(args.id, json.loads(args.data)), as_json)
        elif a == "enable":
            if not args.id:
                parser.error("portforward enable requires id")
            output(client.portforward_toggle(args.id, True), as_json)
        elif a == "disable":
            if not args.id:
                parser.error("portforward disable requires id")
            output(client.portforward_toggle(args.id, False), as_json)
        elif a == "delete":
            if not args.id:
                parser.error("portforward delete requires id")
            output(client.portforward_delete(args.id), as_json)

    elif args.cmd == "vpn":
        output(client.vpn_status(), as_json)

    elif args.cmd == "events":
        output(client.events(args.hours), as_json)

    elif args.cmd == "alarms":
        if args.action == "archive-all":
            output(client.alarms_archive_all(), as_json)
        elif args.action == "archive":
            if not args.id:
                parser.error("alarms archive requires id")
            output(client.alarm_archive(args.id), as_json)
        else:
            output(client.alarms(), as_json)

    elif args.cmd == "stats":
        t = args.type
        if t == "dpi":
            output(client.stats_dpi(), as_json)
        elif t == "gateway":
            output(client.stats_gateway(), as_json)
        elif t == "report":
            output(client.stats_report(args.interval), as_json)

    elif args.cmd == "routes":
        output(client.routes(), as_json)

    elif args.cmd == "ddns":
        output(client.ddns(), as_json)

    elif args.cmd == "raw":
        body = json.loads(args.data) if args.data else None
        output(client.raw(args.method, args.path, body), as_json)


if __name__ == "__main__":
    main()
