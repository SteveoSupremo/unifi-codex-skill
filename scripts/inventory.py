#!/usr/bin/env python3
"""Sanitized, read-only UniFi inventory collector with site discovery."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from unifi_common import load_env, redact


DISCOVERY_ENDPOINT = "/proxy/network/integration/v1/sites"
SITE_READ_ENDPOINTS = [
    "/proxy/network/api/s/{site}/stat/health",
    "/proxy/network/api/s/{site}/rest/networkconf",
    "/proxy/network/api/s/{site}/stat/device",
    "/proxy/network/api/s/{site}/rest/firewallrule",
    "/proxy/network/api/s/{site}/rest/portforward",
    "/proxy/network/v2/api/site/{site}/trafficrules",
]


@dataclass(frozen=True)
class SelectedSite:
    """Official site identity plus the key required by legacy/private APIs."""

    integration_id: str
    internal_reference: str
    name: str

    def as_dict(self) -> dict[str, str]:
        return {
            "id": self.integration_id,
            "internalReference": self.internal_reference,
            "name": self.name,
        }


class SiteDiscoveryError(ValueError):
    def __init__(self, message: str, available_sites: list[dict[str, str]] | None = None):
        super().__init__(message)
        self.available_sites = available_sites or []


def _site_records(response: Any) -> list[dict[str, Any]]:
    """Accept the official envelope or UDMClient's already-unwrapped data list."""
    records = response.get("data") if isinstance(response, dict) else response
    if not isinstance(records, list):
        raise SiteDiscoveryError("site discovery returned a malformed response")
    return [record for record in records if isinstance(record, dict)]


def _site_summary(record: dict[str, Any]) -> dict[str, str]:
    return {
        "id": str(record.get("id") or ""),
        "internalReference": str(record.get("internalReference") or ""),
        "name": str(record.get("name") or ""),
    }


def select_site(response: Any, override: str | None = None) -> SelectedSite:
    """Select without guessing; internalReference scopes legacy/private endpoints."""
    records = _site_records(response)
    summaries = [_site_summary(record) for record in records]
    valid = [site for site in summaries if site["id"] and site["internalReference"]]

    if not records:
        raise SiteDiscoveryError("site discovery returned no sites")
    if len(valid) != len(records):
        raise SiteDiscoveryError(
            "site discovery returned a site without id/internalReference", summaries
        )

    chosen: dict[str, str] | None = None
    if override:
        matches = [
            site
            for site in valid
            if override in (site["id"], site["internalReference"], site["name"])
        ]
        if len(matches) == 1:
            chosen = matches[0]
        elif len(matches) > 1:
            raise SiteDiscoveryError(
                f"UNIFI_SITE={override!r} matches multiple sites", summaries
            )
        else:
            raise SiteDiscoveryError(
                f"UNIFI_SITE={override!r} does not match a discovered site", summaries
            )
    elif len(valid) == 1:
        chosen = valid[0]
    else:
        raise SiteDiscoveryError(
            "multiple sites discovered; set UNIFI_SITE to an id, internalReference, or name",
            summaries,
        )

    return SelectedSite(
        integration_id=chosen["id"],
        internal_reference=chosen["internalReference"],
        name=chosen["name"],
    )


def build_plan(override: str | None = None) -> dict[str, Any]:
    site = override or "<discovered-site>"
    return {
        "mode": "READ_ONLY",
        "stages": [
            {
                "stage": "discover_site",
                "requests": [{"method": "GET", "endpoint": DISCOVERY_ENDPOINT}],
            },
            {
                "stage": "collect_site_inventory",
                "site": site,
                "depends_on": "discover_site",
                "requests": [
                    {"method": "GET", "endpoint": endpoint.format(site=site)}
                    for endpoint in SITE_READ_ENDPOINTS
                ],
            },
        ],
    }


def collect_inventory(client: Any, override: str | None = None) -> dict[str, Any]:
    """Discover first, then perform only GET-backed site-scoped reads."""
    sites = client.get(client._integration("sites"))
    selected = select_site(sites, override)
    client.site = selected.internal_reference
    return {
        "site": selected.as_dict(),
        "status": client.status(),
        "networks": client.networks(),
        "devices": client.devices(),
        "firewall_rules": client.firewall_rules(),
        "traffic_rules": client.traffic_rules(),
        "port_forwards": client.portforward_rules(),
    }


def _format_discovery_error(error: SiteDiscoveryError) -> str:
    return json.dumps(
        {
            "mode": "READ_ONLY",
            "error": str(error),
            "available_sites": redact(error.available_sites),
            "collection_stopped": True,
        },
        indent=2,
        sort_keys=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    env = load_env()
    override = env.get("UNIFI_SITE") or None

    if args.plan:
        print(json.dumps(build_plan(override), indent=2))
        return
    if not env.get("UDM_HOST") or not env.get("UNIFI_API_KEY"):
        raise SystemExit(
            "UDM_HOST and UNIFI_API_KEY are required; use --plan without credentials"
        )

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
