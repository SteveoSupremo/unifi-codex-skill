#!/usr/bin/env python3
"""Sanitized, GET-only UniFi inventory collector with graceful coverage gaps."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).parent))
from unifi_common import load_env, redact


INTEGRATION = "/proxy/network/integration/v1"
DISCOVERY_ENDPOINT = f"{INTEGRATION}/sites"
APPLICATION_INFO_ENDPOINT = f"{INTEGRATION}/info"
PAGE = "?offset=0&limit=200"


@dataclass(frozen=True)
class EndpointSpec:
    dataset: str
    endpoint: str
    api_family: str
    purpose: str
    paginated: bool = False


SITE_READS = [
    EndpointSpec("health", "/proxy/network/api/s/{internal}/stat/health", "legacy/private", "site health"),
    EndpointSpec("sysinfo", "/proxy/network/api/s/{internal}/stat/sysinfo", "legacy/private", "controller and Network version evidence"),
    EndpointSpec("networks", "/proxy/network/api/s/{internal}/rest/networkconf", "legacy/private", "full network configuration"),
    EndpointSpec("devices", "/proxy/network/api/s/{internal}/stat/device", "legacy/private", "full device inventory and health"),
    EndpointSpec("firewall_rules", "/proxy/network/api/s/{internal}/rest/firewallrule", "legacy/private", "legacy firewall rules"),
    EndpointSpec("traffic_rules", "/proxy/network/v2/api/site/{internal}/trafficrules", "private/v2", "traffic rules"),
    EndpointSpec("port_forwards", "/proxy/network/api/s/{internal}/rest/portforward", "legacy/private", "configured port forwards"),
    EndpointSpec("client_configurations", "/proxy/network/api/s/{internal}/rest/user", "legacy/private", "authoritative configured-client and fixed-IP reservation state"),
    EndpointSpec("legacy_clients", "/proxy/network/api/s/{internal}/stat/alluser", "legacy/private", "offline and historical client identity/network context"),
    EndpointSpec("clients", f"{INTEGRATION}/sites/{{site_id}}/clients{PAGE}", "official/integration-v1", "connected clients", True),
    EndpointSpec("firewall_zones", f"{INTEGRATION}/sites/{{site_id}}/firewall/zones{PAGE}", "official/integration-v1", "firewall zones", True),
    EndpointSpec("firewall_policies", f"{INTEGRATION}/sites/{{site_id}}/firewall/policies{PAGE}", "official/integration-v1", "zone firewall policies", True),
    EndpointSpec("wlans", f"{INTEGRATION}/sites/{{site_id}}/wifi/broadcasts{PAGE}", "official/integration-v1", "Wi-Fi broadcasts and security summaries", True),
    EndpointSpec("wan_interfaces", f"{INTEGRATION}/sites/{{site_id}}/wans{PAGE}", "official/integration-v1", "WAN interface definitions", True),
    EndpointSpec("vpn_servers", f"{INTEGRATION}/sites/{{site_id}}/vpn/servers{PAGE}", "official/integration-v1", "VPN server state", True),
    EndpointSpec("vpn_site_to_site", f"{INTEGRATION}/sites/{{site_id}}/vpn/site-to-site-tunnels{PAGE}", "official/integration-v1", "site-to-site VPN state", True),
    EndpointSpec("upnp_exposure", "/proxy/network/api/s/{internal}/stat/portforward", "legacy/private", "configured and dynamically reported forwarding/UPnP exposure"),
    EndpointSpec("ids_ips", "/proxy/network/api/s/{internal}/rest/setting/ips", "legacy/private", "IDS/IPS security settings"),
]


@dataclass(frozen=True)
class SelectedSite:
    integration_id: str
    internal_reference: str
    name: str

    def as_dict(self) -> dict[str, str]:
        return {"id": self.integration_id, "internalReference": self.internal_reference, "name": self.name}


class SiteDiscoveryError(ValueError):
    def __init__(self, message: str, available_sites: list[dict[str, str]] | None = None):
        super().__init__(message)
        self.available_sites = available_sites or []


def _site_records(response: Any) -> list[dict[str, Any]]:
    records = response.get("data") if isinstance(response, dict) else response
    if not isinstance(records, list):
        raise SiteDiscoveryError("site discovery returned a malformed response")
    return [record for record in records if isinstance(record, dict)]


def _site_summary(record: dict[str, Any]) -> dict[str, str]:
    return {"id": str(record.get("id") or ""), "internalReference": str(record.get("internalReference") or ""), "name": str(record.get("name") or "")}


def select_site(response: Any, override: str | None = None) -> SelectedSite:
    records = _site_records(response)
    summaries = [_site_summary(record) for record in records]
    valid = [site for site in summaries if site["id"] and site["internalReference"]]
    if not records:
        raise SiteDiscoveryError("site discovery returned no sites")
    if len(valid) != len(records):
        raise SiteDiscoveryError("site discovery returned a site without id/internalReference", summaries)
    if override:
        matches = [site for site in valid if override in (site["id"], site["internalReference"], site["name"])]
        if len(matches) != 1:
            message = f"UNIFI_SITE={override!r} " + ("matches multiple sites" if matches else "does not match a discovered site")
            raise SiteDiscoveryError(message, summaries)
        chosen = matches[0]
    elif len(valid) == 1:
        chosen = valid[0]
    else:
        raise SiteDiscoveryError("multiple sites discovered; set UNIFI_SITE to an id, internalReference, or name", summaries)
    return SelectedSite(chosen["id"], chosen["internalReference"], chosen["name"])


def _request_record(spec: EndpointSpec, site: str) -> dict[str, Any]:
    endpoint = spec.endpoint.format(site_id=site, internal=site)
    record: dict[str, Any] = {"dataset": spec.dataset, "method": "GET", "endpoint": endpoint,
        "api_family": spec.api_family, "purpose": spec.purpose, "optional": True}
    if spec.paginated:
        record["pagination"] = "repeat GET with offset += limit while offset + count < totalCount"
    return record


def build_plan(override: str | None = None) -> dict[str, Any]:
    integration_site = override or "<discovered-site-id>"
    internal = override or "<discovered-internal-reference>"
    requests = []
    for spec in SITE_READS:
        site = integration_site if "{site_id}" in spec.endpoint else internal
        requests.append(_request_record(spec, site))
    return {"mode": "READ_ONLY", "live_mutation": False,
        "unsupported_behavior": "record dataset as unavailable and continue",
        "stages": [
            {"stage":"identify_application_version","requests":[{"dataset":"application_info","method":"GET","endpoint":APPLICATION_INFO_ENDPOINT,"api_family":"official/integration-v1","purpose":"authoritative installed Network API version","optional":True}]},
            {"stage":"discover_site","requests":[{"dataset":"sites","method":"GET","endpoint":DISCOVERY_ENDPOINT,"api_family":"official/integration-v1","purpose":"site identity and legacy internal reference","optional":False}]},
            {"stage":"collect_site_inventory","site_id":integration_site,"internal_reference":internal,"depends_on":"discover_site","requests":requests},
        ]}


def _url(client: Any, endpoint: str) -> str:
    base = getattr(client, "base", "").rstrip("/")
    return f"{base}{endpoint}" if base else endpoint


def _get_optional(client: Any, endpoint: str, *, unwrap: bool = False) -> Any:
    getter: Callable[..., Any] = getattr(client, "get_optional", client.get)
    try:
        try:
            return getter(_url(client, endpoint), unwrap=unwrap)
        except TypeError:
            return getter(_url(client, endpoint))
    except (Exception, SystemExit) as error:
        status = getattr(error, "status", None)
        return {"_unavailable": True, "reason": f"HTTP {status}" if status else "unsupported or transport unavailable"}


def _unwrap_page(response: Any) -> tuple[list[Any] | None, dict[str, Any] | None]:
    if isinstance(response, dict) and response.get("_unavailable"):
        return None, response
    if isinstance(response, list):
        return response, None
    if isinstance(response, dict) and isinstance(response.get("data"), list):
        return response["data"], None
    if isinstance(response, dict):
        return [response], None
    return None, {"_unavailable": True, "reason": "malformed response"}


def _collect_spec(client: Any, selected: SelectedSite, spec: EndpointSpec) -> tuple[Any, dict[str, Any]]:
    endpoint = spec.endpoint.format(site_id=selected.integration_id, internal=selected.internal_reference)
    response = _get_optional(client, endpoint, unwrap=not spec.paginated)
    records, error = _unwrap_page(response)
    status = {"status":"unavailable" if error else "available", "api_family":spec.api_family, "method":"GET", "endpoint":endpoint}
    if error:
        status["reason"] = error["reason"]
        return None, status
    if spec.paginated and isinstance(response, dict):
        all_records = list(records or [])
        offset = int(response.get("offset", 0)); count = int(response.get("count", len(all_records))); total = int(response.get("totalCount", count)); limit = int(response.get("limit", 200) or 200)
        while offset + count < total:
            offset += limit
            next_endpoint = endpoint.split("?", 1)[0] + f"?offset={offset}&limit={limit}"
            page = _get_optional(client, next_endpoint, unwrap=False)
            page_records, page_error = _unwrap_page(page)
            if page_error:
                status.update(status="partial", reason=page_error["reason"])
                break
            all_records.extend(page_records or []); count = int(page.get("count", len(page_records or []))) if isinstance(page, dict) else len(page_records or [])
        records = all_records
    status["count"] = len(records or [])
    return records or [], status


def _identifier(record: dict[str, Any] | None) -> str | None:
    if not record:
        return None
    value = record.get("id") or record.get("_id")
    return str(value) if value else None


def _mac(record: dict[str, Any]) -> str:
    return str(record.get("mac") or record.get("macAddress") or "").lower()


def discover_fixed_ip_state(configured: list[dict[str, Any]] | None,
                            observed: list[dict[str, Any]] | None,
                            networks: list[dict[str, Any]] | None,
                            mac: str) -> dict[str, Any]:
    """Merge authoritative rest/user configuration with observational client data."""
    normalized = mac.lower()
    configuration = next((item for item in configured or [] if _mac(item) == normalized), None)
    client = next((item for item in observed or [] if _mac(item) == normalized), None)
    source = configuration or client or {}
    override_enabled = source.get("virtual_network_override_enabled")
    override = (source.get("virtual_network_override_id") or
                source.get("network_override_id") or source.get("networkOverrideId") or
                source.get("fixed_network_id") or source.get("fixedNetworkId"))
    if override_enabled is False:
        override = None
    network_id = (override or source.get("network_id") or source.get("networkId") or
                  source.get("last_connection_network_id") or source.get("lastConnectionNetworkId") or
                  (client or {}).get("network_id") or (client or {}).get("networkId"))
    network = next((item for item in networks or [] if _identifier(item) == str(network_id)), None)
    if configuration is None:
        fixed_enabled = None
        fixed_address = None
        authority = "not_available"
    else:
        fixed_enabled = bool(configuration.get("use_fixedip") is True or configuration.get("fixedIpEnabled") is True)
        fixed_address = configuration.get("fixed_ip") or configuration.get("fixedIpAddress")
        authority = "legacy/private rest/user"
    return {
        "client_identity": {"mac": normalized, "name": source.get("name") or source.get("hostname")},
        "configured_client_id": _identifier(configuration),
        "fixed_ip_enabled": fixed_enabled,
        "fixed_ipv4": fixed_address if fixed_enabled else None,
        "leased_ipv4": (client or {}).get("ip") or (client or {}).get("ipAddress"),
        "network_id": str(network_id) if network_id else None,
        "network_name": ((network or {}).get("name") or source.get("last_connection_network_name") or
                         source.get("lastConnectionNetworkName")),
        "vlan_id": (network or {}).get("vlan", (network or {}).get("vlan_id")),
        "network_override": {"id": str(override) if override else None,
                             "enabled": override_enabled if override_enabled is not None else (override is not None),
                             "exposed": any(key in source for key in ("virtual_network_override_enabled",
                                                                       "virtual_network_override_id",
                                                                       "network_override_id", "networkOverrideId"))},
        "authoritative_fixed_ip_source": authority,
        "api_family": "legacy/private" if configuration is not None else "not_available",
        "api_note": "rest/user is version-sensitive and supplies configuration; official connected clients remain observational",
    }


def fixed_ip_states(configured: list[dict[str, Any]] | None,
                    observed_groups: list[list[dict[str, Any]] | None],
                    networks: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for group in [configured, *observed_groups]:
        for record in group or []:
            if _mac(record):
                merged.setdefault(_mac(record), record)
    observed = [record for group in observed_groups for record in (group or [])]
    return [discover_fixed_ip_state(configured, observed, networks, mac) for mac in sorted(merged)]


def collect_inventory(client: Any, override: str | None = None) -> dict[str, Any]:
    """Perform only GET requests; unsupported optional datasets do not abort collection."""
    app_info = _get_optional(client, APPLICATION_INFO_ENDPOINT, unwrap=False)
    sites = _get_optional(client, DISCOVERY_ENDPOINT, unwrap=False)
    if isinstance(sites, dict) and sites.get("_unavailable"):
        raise SiteDiscoveryError("site discovery GET failed")
    selected = select_site(sites, override)
    client.site = selected.internal_reference
    result: dict[str, Any] = {"site": selected.as_dict(), "collection_status": {}, "live_mutation": False}
    if isinstance(app_info, dict) and not app_info.get("_unavailable"):
        result["application_info"] = app_info
        result["collection_status"]["application_info"] = {"status":"available","api_family":"official/integration-v1","method":"GET","endpoint":APPLICATION_INFO_ENDPOINT}
    else:
        result["application_info"] = None
        result["collection_status"]["application_info"] = {"status":"unavailable","api_family":"official/integration-v1","method":"GET","endpoint":APPLICATION_INFO_ENDPOINT}
    for spec in SITE_READS:
        value, status = _collect_spec(client, selected, spec)
        result[spec.dataset] = value
        result["collection_status"][spec.dataset] = status
    result["fixed_ip_states"] = fixed_ip_states(result.get("client_configurations"),
                                                 [result.get("clients"), result.get("legacy_clients")],
                                                 result.get("networks"))
    result["collection_status"]["fixed_ip_states"] = {
        "status": "available" if result.get("client_configurations") is not None else "unavailable",
        "api_family": "derived from legacy/private configuration plus observational clients",
        "method": "local correlation",
        "endpoint": "/proxy/network/api/s/{site}/rest/user",
    }
    result["status"] = {"health": result.pop("health"), "sysinfo": (result.pop("sysinfo") or [None])[0] if result.get("sysinfo") is not None else None}
    result["vpn"] = {"servers": result.pop("vpn_servers"), "site_to_site": result.pop("vpn_site_to_site")}
    return result


def _format_discovery_error(error: SiteDiscoveryError) -> str:
    return json.dumps({"mode":"READ_ONLY","live_mutation":False,"error":str(error),"available_sites":redact(error.available_sites),"collection_stopped":True}, indent=2, sort_keys=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    env = load_env(); override = env.get("UNIFI_SITE") or None
    if args.plan:
        print(json.dumps(build_plan(override), indent=2)); return
    if not env.get("UDM_HOST") or not env.get("UNIFI_API_KEY"):
        raise SystemExit("UDM_HOST and UNIFI_API_KEY are required; use --plan without credentials")
    from udm import UDMClient
    client = UDMClient(env["UDM_HOST"], env["UNIFI_API_KEY"])
    try:
        data = collect_inventory(client, override)
    except SiteDiscoveryError as error:
        raise SystemExit(_format_discovery_error(error)) from error
    text = json.dumps(redact(data), indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(text + "\n")
    else:
        print(text)


if __name__ == "__main__":
    main()
