"""Read-only planning for a local-time, cross-zone Internet restriction."""
from datetime import datetime
import re
from zoneinfo import ZoneInfo

from inventory import collect_inventory, _get_optional

SPEC = "/proxy/network/api-docs/integration.json"
NAME = "Family Overnight Internet Block"
GROUP = "Family-Overnight-Restricted"
TZ = "America/New_York"


def desired_active(instant):
    if instant.tzinfo is None:
        raise ValueError("timezone-aware observation required")
    hour = instant.astimezone(ZoneInfo(TZ)).hour
    return hour >= 20 or hour < 11


def matching(rows, key, value):
    return [row for row in rows or [] if str(row.get(key, "")).lower() == value.lower()]


def plan(data, schema, macs):
    macs = sorted(mac.lower() for mac in macs)
    if not macs or len(set(macs)) != len(macs) or any(
        not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac) for mac in macs
    ):
        raise ValueError("supply distinct confirmed MAC addresses")
    sysinfo = data["status"].get("sysinfo") or {}
    version = (data.get("application_info") or {}).get("applicationVersion")
    paths = schema.get("paths") or {}
    schemas = schema.get("components", {}).get("schemas", {})
    zone_members = {}
    members = []
    blockers = []
    for key in ("clients", "legacy_clients", "networks", "firewall_zones", "wan_interfaces", "firewall_policies"):
        if data.get(key) is None:
            blockers.append(f"{key} unavailable")
    for mac in macs:
        live = matching(data.get("clients"), "macAddress", mac)
        history = matching(data.get("legacy_clients"), "mac", mac)
        record = history[0] if len(history) == 1 else {}
        stations = matching(data.get("active_stations"), "mac", mac)
        station = stations[0] if len(stations) == 1 else {}
        live_network = station.get("network_id")
        network_id = live_network or record.get("last_connection_network_id")
        if len(stations) > 1 or bool(live) != bool(station) or (live and not live_network):
            blockers.append(f"current attachment for {mac} needs reconciliation")
        networks = matching(data.get("networks"), "_id", network_id or "?")
        network = networks[0] if len(networks) == 1 else {}
        zones = [z for z in data.get("firewall_zones") or []
                 if network.get("external_id") in (z.get("networkIds") or [])]
        zone = zones[0] if len(zones) == 1 else {}
        current = live[0] if len(live) == 1 else {}
        if len(live) > 1 or not zone.get("id") or not network.get("external_id"):
            blockers.append(f"ambiguous identity/network/zone for {mac}")
        else:
            zone_members.setdefault(zone["id"], []).append(mac)
        members.append(dict(mac=mac, hostname=record.get("hostname"), live_ip=current.get("ipAddress"),
                            historical_ip=record.get("last_ip"), last_seen=record.get("last_seen"),
                            network=network.get("name"), network_evidence="active station" if live_network else "history",
                            zone=zone.get("name"),
                            historical_group_ids=record.get("network_members_group_ids")))
    external = matching(data.get("firewall_zones"), "name", "External")
    wans = data.get("wan_interfaces") or []
    if len(external) != 1 or not wans or any(w.get("id") not in external[0]["networkIds"] for w in wans):
        blockers.append("External zone and WAN coverage unresolved")
    existing = [p for p in data.get("firewall_policies") or []
                if p.get("name", "").casefold().split(" [")[0] == NAME.casefold()]
    groups = data.get("device_groups")
    matching_groups = matching(groups, "name", GROUP)
    group_status = "unavailable"
    if isinstance(groups, list) and all(isinstance(g, dict) and g.get("name") for g in groups):
        group_status = "present" if len(matching_groups) == 1 else "ambiguous" if matching_groups else "absent"
    candidates = []
    if len(external) == 1:
        for zid, addresses in sorted(zone_members.items()):
            zone = next(z for z in data["firewall_zones"] if z["id"] == zid)
            candidates.append(dict(name=f"{NAME} [{zone['name']}]", enabled=True, action={"type": "BLOCK"},
                source={"zoneId": zid, "trafficFilter": {"type": "MAC_ADDRESS",
                    "macAddressFilter": {"macAddresses": addresses}}}, destination={"zoneId": external[0]["id"]},
                ipProtocolScope={"ipVersion": "IPV4_AND_IPV6"}, loggingEnabled=True,
                schedule={"mode": "EVERY_DAY", "timeFilter": {"startTime": "20:00", "stopTime": "11:00"}}))
    if existing:
        blockers.append("reconcile existing IDs, origins, membership and ordering before any change")
    if sysinfo.get("timezone") != TZ:
        blockers.append("controller timezone differs or unavailable")
    if not paths or schema.get("info", {}).get("version") != version or version != "10.6.109":
        blockers.append("installed schema unavailable, mismatched or unreviewed")
    blockers.extend(["confirm native group identity and dependencies in Object Manager",
                     "verify next-day end, end exclusivity and DST on this build",
                     "resolve policy routes, alternate Internet exits and current device attachment"])
    return dict(observed_at=data["collection_finished_at"], network_version=version,
                gateway_firmware=sysinfo.get("udm_version"), controller_timezone=sysinfo.get("timezone"),
                schema_version=schema.get("info", {}).get("version"), official_path_count=len(paths),
                firewall_methods=sorted(k for k in paths.get("/v1/sites/{siteId}/firewall/policies", {}) if k in {"get","post"}),
                daily_schedule_schema="IntegrationFirewallScheduleEveryDayDto" in schemas,
                group_related_paths=sorted(p for p in paths if "group" in p.lower()),
                requested_group=GROUP, group_status=group_status,
                authoritative_group_membership=[] if group_status == "absent" else None,
                group_ids=[g.get("id", g.get("_id")) for g in matching_groups],
                policy_route_count=len(data["policy_routes"]) if isinstance(data.get("policy_routes"), list) else None,
                source_to_external_policy_order=[
                    {k: r.get(k) for k in ("id", "index", "name", "enabled", "action")}
                    for r in sorted(data.get("firewall_policies") or [], key=lambda p: p.get("index", 0))
                    if r.get("source", {}).get("zoneId") in zone_members and len(external) == 1
                    and r.get("destination", {}).get("zoneId") == external[0]["id"]],
                requested_members=members,
                wan_interfaces=wans, existing_policy_readback=[
                    {k: policy.get(k) for k in ("id", "name", "enabled", "source", "destination",
                     "action", "schedule", "ipProtocolScope", "loggingEnabled", "index", "metadata")}
                    for policy in existing], candidate_zone_policies=candidates,
                desired_active_at_observation=desired_active(datetime.fromisoformat(data["collection_finished_at"])),
                observed_blocked_traffic=None, persistence_verified=None, approval_available=False, blockers=blockers)


def discover(client, site, macs):
    schema = _get_optional(client, SPEC)
    inventory = collect_inventory(client, site)
    stations = _get_optional(client, f"/proxy/network/api/s/{client.site}/stat/sta", unwrap=True)
    inventory["active_stations"] = stations if isinstance(stations, list) else None
    for dataset, endpoint in (("device_groups", "network-members-groups"), ("policy_routes", "trafficroutes")):
        rows = _get_optional(client, f"/proxy/network/v2/api/site/{client.site}/{endpoint}")
        inventory[dataset] = rows if isinstance(rows, list) and all(isinstance(r, dict) for r in rows) else None
    return plan(inventory, schema if isinstance(schema, dict) else {}, macs)
