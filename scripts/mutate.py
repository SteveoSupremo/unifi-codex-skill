#!/usr/bin/env python3
"""Guarded UniFi mutation CLI.  There is no raw-write escape hatch here."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from inventory import APPLICATION_INFO_ENDPOINT, DISCOVERY_ENDPOINT, select_site
from mutationlib import ControllerIdentity, GuardedMutator, MutationError, StateMismatch
from snapshot import SnapshotError
from unifi_common import load_env


def _json_file(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise argparse.ArgumentTypeError("input must be a readable JSON file") from error
    if not isinstance(value, dict):
        raise argparse.ArgumentTypeError("input JSON must be an object")
    return value


def _expected(values: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--expect must use FIELD=JSON_VALUE")
        field, raw = value.split("=", 1)
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = raw
        result[field] = parsed
    return result


def _approval(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--plan", action="store_true", help="GET, snapshot, diff, and validate without writing")
    group.add_argument("--approve", metavar="TOKEN", help="exact token emitted by a matching --plan")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Guarded UniFi configuration mutations")
    resources = root.add_subparsers(dest="resource", required=True)

    pf = resources.add_parser("port-forward")
    pf_actions = pf.add_subparsers(dest="action", required=True)
    delete = pf_actions.add_parser("delete")
    delete.add_argument("--id", required=True)
    delete.add_argument("--expect", action="append", default=[], metavar="FIELD=VALUE")
    _approval(delete)
    restore = pf_actions.add_parser("restore")
    restore.add_argument("--snapshot", required=True, type=Path)
    _approval(restore)

    client = resources.add_parser("client")
    client_actions = client.add_subparsers(dest="action", required=True)
    fixed = client_actions.add_parser("fixed-ip")
    fixed_actions = fixed.add_subparsers(dest="fixed_action", required=True)
    set_ip = fixed_actions.add_parser("set")
    set_ip.add_argument("--mac", required=True)
    set_ip.add_argument("--ip", required=True)
    _approval(set_ip)
    remove_ip = fixed_actions.add_parser("remove")
    remove_ip.add_argument("--mac", required=True)
    _approval(remove_ip)

    firewall = resources.add_parser("firewall")
    firewall_resources = firewall.add_subparsers(dest="firewall_resource", required=True)
    policy = firewall_resources.add_parser("policy")
    policy_actions = policy.add_subparsers(dest="policy_action", required=True)
    create = policy_actions.add_parser("create")
    create.add_argument("--input", required=True, type=Path)
    _approval(create)
    update = policy_actions.add_parser("update")
    update.add_argument("--id", required=True)
    update.add_argument("--input", required=True, type=Path, help="JSON object containing top-level changes")
    _approval(update)
    remove = policy_actions.add_parser("delete")
    remove.add_argument("--id", required=True)
    _approval(remove)
    return root


def _discover(client: Any, override: str | None):
    base = str(getattr(client, "base", "")).rstrip("/")
    endpoint = f"{base}{DISCOVERY_ENDPOINT}" if base else DISCOVERY_ENDPOINT
    optional = getattr(client, "get_optional", None)
    if optional:
        return select_site(optional(endpoint, unwrap=False), override)
    return select_site(client.get(endpoint), override)


def _controller_identity(client: Any, host: str, override: str | None) -> ControllerIdentity:
    site = _discover(client, override)
    base = str(getattr(client, "base", "")).rstrip("/")
    endpoint = f"{base}{APPLICATION_INFO_ENDPOINT}" if base else APPLICATION_INFO_ENDPOINT
    optional = getattr(client, "get_optional", None)
    info = optional(endpoint, unwrap=False) if optional else client.get(endpoint)
    if isinstance(info, dict) and isinstance(info.get("data"), dict):
        info = info["data"]
    if isinstance(info, dict) and isinstance(info.get("data"), list) and info["data"]:
        info = info["data"][0]
    version = (info or {}).get("applicationVersion") if isinstance(info, dict) else None
    if not version:
        raise StateMismatch("UniFi Network version could not be established; mutation planning is refused")
    return ControllerIdentity(host, site.integration_id, site.internal_reference, site.name, str(version))


def main() -> None:
    command_parser = parser()
    args = command_parser.parse_args()
    env = load_env()
    if not env.get("UDM_HOST") or not env.get("UNIFI_API_KEY"):
        command_parser.error("UDM_HOST and UNIFI_API_KEY are required for current-state GETs")
    from udm import UDMClient
    client = UDMClient(env["UDM_HOST"], env["UNIFI_API_KEY"])
    try:
        override = env.get("UNIFI_SITE") or None
        identity = _controller_identity(client, env["UDM_HOST"], override)
        mutator = GuardedMutator(client, site_id=identity.site_id,
                                 internal_site=identity.internal_reference, env=env,
                                 controller_host=identity.controller_host,
                                 site_name=identity.site_name,
                                 network_version=identity.network_version,
                                 identity_reader=lambda: _controller_identity(client, env["UDM_HOST"], override))
        dry_run = bool(getattr(args, "plan", False))
        approval = getattr(args, "approve", None)
        if args.resource == "port-forward" and args.action == "delete":
            result = mutator.port_forward_delete(args.id, expected=_expected(args.expect),
                                                  dry_run=dry_run, approval=approval)
        elif args.resource == "port-forward":
            result = mutator.port_forward_restore(args.snapshot, dry_run=dry_run, approval=approval)
        elif args.resource == "client":
            address = args.ip if args.fixed_action == "set" else None
            result = mutator.fixed_ip_change(args.mac, address, dry_run=dry_run, approval=approval)
        elif args.policy_action == "create":
            result = mutator.firewall_policy_create(_json_file(args.input), dry_run=dry_run, approval=approval)
        elif args.policy_action == "update":
            result = mutator.firewall_policy_update(args.id, _json_file(args.input), dry_run=dry_run, approval=approval)
        else:
            result = mutator.firewall_policy_delete(args.id, dry_run=dry_run, approval=approval)
    except (MutationError, SnapshotError, PermissionError, ValueError) as error:
        payload = {"error": str(error), "write_performed": False}
        if getattr(error, "details", None):
            payload["details"] = error.details
        raise SystemExit(json.dumps(payload, indent=2)) from error
    # MutationPlan.public() and verification results are already recursively
    # sanitized.  A second generic pass would hide the non-secret approval token.
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
