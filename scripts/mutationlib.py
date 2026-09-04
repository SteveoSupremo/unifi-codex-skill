#!/usr/bin/env python3
"""Guarded UniFi configuration mutations.

This module is intentionally separate from the upstream ``udm.py`` CLI.  Every
write reachable here is prepared by the same GET/snapshot/diff/validate/approve
gate, and tests inject a transport so no controller is contacted.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import ipaddress
import json
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from operation_journal import OperationJournal, new_operation_id, utc_now
from snapshot import SnapshotError, create_snapshot, load_snapshot
from unifi_common import ROOT, WRITE_PHRASE, json_diff, redact, writes_enabled


INTEGRATION = "/proxy/network/integration/v1"
VOLATILE_KEYS = {
    "createdAt", "updatedAt", "created_at", "updated_at", "timestamp",
    "observedAt", "observed_at", "observationTimestamp", "observation_timestamp",
    "collectedAt", "collected_at", "generatedAt", "generated_at",
    "leaseAge", "lease_age", "lastSeen", "last_seen",
}
IDENTITY_KEYS = {"id", "_id"}
POLICY_ORIGINS_PROTECTED = {"SYSTEM_DEFINED", "DERIVED"}
POLICY_ACTIONS = {"ALLOW", "BLOCK", "REJECT"}
CONNECTION_STATES = {"NEW", "ESTABLISHED", "RELATED", "INVALID"}
IP_VERSIONS = {"IPV4", "IPV6", "IPV4_AND_IPV6", "BOTH"}
RESERVATION_SEMANTICS = "UniFi DHCP reservations may be inside or outside the dynamic pool"
_UNSET = object()


class MutationError(RuntimeError):
    """A sanitized, expected mutation-planning or verification failure."""


class ValidationError(MutationError):
    pass


class StateMismatch(MutationError):
    pass


class VerificationError(MutationError):
    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.details = details or {}


class StaleApprovalError(MutationError):
    pass


class AmbiguousWriteError(MutationError):
    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.details = details or {}


@dataclass(frozen=True)
class ControllerIdentity:
    controller_host: str
    site_id: str
    internal_reference: str
    site_name: str
    network_version: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def normalize_state(value: Any) -> Any:
    """Produce a deterministic, complete JSON-compatible state representation."""
    if isinstance(value, dict):
        return {str(key): normalize_state(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, list):
        return [normalize_state(item) for item in value]
    if isinstance(value, tuple):
        return [normalize_state(item) for item in value]
    return value


def state_fingerprint(value: Any) -> str:
    payload = json.dumps(normalize_state(value), sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class MutationPlan:
    operation_id: str
    timestamp: str
    controller_identity: dict[str, str]
    operation: str
    target_object_type: str
    target_identity: dict[str, Any]
    current_state: Any
    proposed_state: Any
    diff: str
    safety_level: int
    snapshot_path: str
    expected_generated_effects: list[str]
    validation_steps: list[str]
    rollback_path: str
    current_state_fingerprint: str
    proposed_state_fingerprint: str
    precondition_fingerprint: str
    approval_fingerprint: str
    approval_token: str
    mutation_method: str
    mutation_endpoint: str
    operation_record: str
    current_get_succeeded: bool = True
    snapshot_created: bool = True
    validated: bool = True
    logical_mutations: int = 1
    approved_state: Any = field(default=None, repr=False)
    precondition_state: Any = field(default=None, repr=False)
    approval_material: Any = field(default=None, repr=False)

    def public(self) -> dict[str, Any]:
        hidden = {"approved_state", "precondition_state"}
        result = {key: value for key, value in asdict(self).items() if key not in hidden}
        result["current_state"] = redact(self.current_state)
        result["proposed_state"] = redact(self.proposed_state)
        result["safety_block"] = {
            "Controller": self.controller_identity["controller_host"],
            "Site": f'{self.controller_identity["site_name"]} ({self.controller_identity["site_id"]}; {self.controller_identity["internal_reference"]})',
            "Network version": self.controller_identity["network_version"],
            "Operation": self.operation,
            "Target": self.target_identity,
            "Safety level": self.safety_level,
            "Write gate": "disabled for plan; exact environment phrase plus matching token required for execution",
            "Snapshot": self.snapshot_path,
            "Current-state fingerprint": self.current_state_fingerprint,
            "Precondition fingerprint": self.precondition_fingerprint,
            "Proposed-state fingerprint": self.proposed_state_fingerprint,
            "Expected secondary effects": self.expected_generated_effects,
            "Verification": self.validation_steps,
            "Rollback": self.rollback_path,
            "Approval token": self.approval_token,
            "Notice": "NO WRITE HAS OCCURRED.",
        }
        return result


class MutationGate:
    """The sole authorization point used immediately before a transport write."""

    @staticmethod
    def authorize(plan: MutationPlan, approval: str | None, env: dict[str, str]) -> None:
        if env.get("UNIFI_ENABLE_WRITES") != WRITE_PHRASE or not writes_enabled(env):
            raise PermissionError("live writes are disabled; the exact enablement phrase is required")
        if not approval:
            raise PermissionError("an explicit operation approval token is required")
        fingerprint = approval_fingerprint(plan.approval_material)
        expected_token = approval_token(plan.operation, plan.target_identity, fingerprint)
        if fingerprint != plan.approval_fingerprint or plan.approval_token != expected_token:
            raise PermissionError("plan fingerprint is internally inconsistent")
        if approval != expected_token:
            raise PermissionError("approval token does not match the exact current/proposed operation")
        if not plan.current_get_succeeded:
            raise PermissionError("a successful current-state GET is required")
        if not plan.snapshot_created or not Path(plan.snapshot_path).is_dir():
            raise PermissionError("a full rollback snapshot is required")
        try:
            load_snapshot(Path(plan.snapshot_path), expected_identity=plan.controller_identity)
        except SnapshotError as error:
            raise PermissionError("rollback snapshot integrity or controller/site identity check failed") from error
        if not plan.diff:
            raise PermissionError("an exact before/after diff is required")
        if not plan.validated:
            raise PermissionError("proposed mutation has not passed validation")
        if plan.logical_mutations != 1:
            raise PermissionError("exactly one logical mutation is allowed")


def approval_fingerprint(material: Any) -> str:
    """Hash canonical, operation-specific approval material only."""
    return state_fingerprint(material)


def approval_token(operation: str, target: Any, fingerprint: str) -> str:
    operation_code = {"port-forward.delete": "DELETE-PF", "port-forward.restore": "RESTORE-PF",
                      "client.fixed-ip.set": "SET-FIXED-IP", "client.fixed-ip.remove": "REMOVE-FIXED-IP",
                      "firewall-policy.create": "CREATE-FW", "firewall-policy.update": "UPDATE-FW",
                      "firewall-policy.delete": "DELETE-FW"}.get(operation, "MUTATE")
    stable = str(target.get("id") or target.get("mac") or target.get("original_id") or "NEW")
    return f"{operation_code}-{stable[:8]}-{fingerprint[:10].upper()}"


def _records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict) and isinstance(value.get("data"), list):
        value = value["data"]
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise StateMismatch("controller returned a malformed object collection")
    return value


def object_id(value: dict[str, Any]) -> str:
    return str(value.get("id") or value.get("_id") or "")


def _find(records: Iterable[dict[str, Any]], identifier: str) -> dict[str, Any] | None:
    return next((item for item in records if object_id(item) == identifier), None)


def _get_path(value: Any, dotted: str) -> Any:
    current = value
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            raise StateMismatch(f"expected field {dotted!r} is absent")
        current = current[part]
    return current


def verify_expected(current: dict[str, Any], expected: dict[str, Any] | None) -> None:
    for field, value in (expected or {}).items():
        if _get_path(current, field) != value:
            raise StateMismatch(f"current-state mismatch for {field!r}")


def _strip_keys(value: Any, keys: set[str]) -> Any:
    if isinstance(value, dict):
        return {k: _strip_keys(v, keys) for k, v in value.items() if k not in keys}
    if isinstance(value, list):
        return [_strip_keys(v, keys) for v in value]
    return value


def _stable_collection(records: list[dict[str, Any]], *, ordered: bool = False) -> list[dict[str, Any]]:
    """Remove known telemetry and canonicalize semantically unordered collections."""
    stable = [_strip_keys(record, VOLATILE_KEYS) for record in records]
    if ordered:
        def order_key(item: dict[str, Any]) -> tuple[int, int | str, str]:
            value = item.get("index", item.get("order", 0))
            return (0, value, object_id(item)) if isinstance(value, int) else (1, str(value), object_id(item))
        return sorted(stable, key=order_key)
    return sorted(stable, key=lambda item: (object_id(item), state_fingerprint(item)))


def _deep_merge(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """Deep-copy a full object and minimally replace only supplied fields."""
    result = copy.deepcopy(current)
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _contains(actual: Any, expected: Any) -> bool:
    """True when actual contains the complete normalized expected structure."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and _contains(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(_contains(a, e) for a, e in zip(actual, expected))
    return actual == expected


def _recursive_values(value: Any) -> list[str]:
    values: list[str] = []
    if isinstance(value, dict):
        for child in value.values():
            values.extend(_recursive_values(child))
    elif isinstance(value, list):
        for child in value:
            values.extend(_recursive_values(child))
    elif value is not None:
        values.append(str(value).lower())
    return values


def _port_forward_markers(rule: dict[str, Any]) -> set[str]:
    markers = {object_id(rule), str(rule.get("name") or ""), str(rule.get("fwd") or rule.get("forwardIp") or ""),
               str(rule.get("dst_port") or rule.get("destinationPort") or "")}
    return {marker.lower() for marker in markers if marker}


def _related(records: list[dict[str, Any]], rule: dict[str, Any]) -> list[dict[str, Any]]:
    strong = {object_id(rule).lower()} - {""}
    weak = _port_forward_markers(rule) - strong
    matches = []
    for record in records:
        values = _recursive_values(record)
        if any(marker in values for marker in strong) or (len([marker for marker in weak if marker in values]) >= 2):
            matches.append(record)
    return matches


def _semantics(value: Any) -> Any:
    return _strip_keys(value, VOLATILE_KEYS | IDENTITY_KEYS)


def _port_forward_signature(rule: dict[str, Any]) -> dict[str, Any]:
    return _semantics(rule)


def _policy_origin(policy: dict[str, Any]) -> str:
    metadata = policy.get("metadata") if isinstance(policy.get("metadata"), dict) else {}
    return str(metadata.get("origin") or policy.get("origin") or policy.get("type") or "").upper()


def _policy_order_signature(policies: list[dict[str, Any]], exclude: set[str] | None = None) -> list[dict[str, Any]]:
    excluded = exclude or set()
    return [{"id": object_id(item), "index": item.get("index", item.get("order")),
             "origin": _policy_origin(item)}
            for item in policies if object_id(item) not in excluded]


def _policy_snapshot(policies: list[dict[str, Any]], target: dict[str, Any] | None,
                     zones: list[dict[str, Any]]) -> dict[str, Any]:
    target_id = object_id(target or {})
    positions = [index for index, item in enumerate(policies) if object_id(item) == target_id]
    position = positions[0] if positions else None
    neighbors = []
    if position is not None:
        neighbors = [policies[index] for index in (position - 1, position + 1)
                     if 0 <= index < len(policies)]
    elif target and isinstance(target.get("index", target.get("order")), int):
        target_index = target.get("index", target.get("order"))
        lower = [item for item in policies
                 if isinstance(item.get("index", item.get("order")), int) and
                 item.get("index", item.get("order")) <= target_index]
        upper = [item for item in policies
                 if isinstance(item.get("index", item.get("order")), int) and
                 item.get("index", item.get("order")) > target_index]
        if lower:
            neighbors.append(max(lower, key=lambda item: item.get("index", item.get("order"))))
        if upper:
            neighbors.append(min(upper, key=lambda item: item.get("index", item.get("order"))))
    zone_ids = set()
    if target:
        for side in ("source", "destination"):
            value = target.get(side)
            if isinstance(value, dict) and value.get("zoneId"):
                zone_ids.add(str(value["zoneId"]))
    return {"target": target, "neighbors": neighbors,
            "complete_policy_order": _policy_order_signature(policies),
            "related_zones": [zone for zone in zones if object_id(zone) in zone_ids]}


def _policy_direction(policy: dict[str, Any], zones: list[dict[str, Any]]) -> str:
    names = {object_id(zone): str(zone.get("name") or object_id(zone)) for zone in zones}
    source = policy.get("source") if isinstance(policy.get("source"), dict) else {}
    destination = policy.get("destination") if isinstance(policy.get("destination"), dict) else {}
    source_id = str(source.get("zoneId") or "unknown")
    destination_id = str(destination.get("zoneId") or "unknown")
    return f"{names.get(source_id, source_id)} -> {names.get(destination_id, destination_id)}"


def _validate_port_forward(rule: dict[str, Any]) -> list[str]:
    if not isinstance(rule, dict) or not object_id(rule):
        raise ValidationError("port-forward object must include an id")
    if not (rule.get("name") or rule.get("fwd") or rule.get("forwardIp")):
        raise ValidationError("port-forward object lacks recognizable identity fields")
    return ["authoritative port-forward object has an id and recognizable identity"]


def _walk_address_values(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        item_type = str(value.get("type") or "").upper()
        raw = value.get("value")
        if raw is not None and item_type in {"IP_ADDRESS", "SUBNET", "IP_RANGE"}:
            yield str(raw)
        for child in value.values():
            yield from _walk_address_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_address_values(child)


def _validate_address(value: str) -> None:
    try:
        if "-" in value:
            start, end = value.split("-", 1)
            if ipaddress.ip_address(start.strip()) > ipaddress.ip_address(end.strip()):
                raise ValueError
        elif "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError as error:
        raise ValidationError("firewall policy contains an invalid address or range") from error


def _collect_named_refs(value: Any, singular: str, plural: str) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        if singular in value and value[singular] is not None:
            found.add(str(value[singular]))
        if plural in value and isinstance(value[plural], list):
            found.update(str(item) for item in value[plural])
        for child in value.values():
            found.update(_collect_named_refs(child, singular, plural))
    elif isinstance(value, list):
        for child in value:
            found.update(_collect_named_refs(child, singular, plural))
    return found


def validate_policy(policy: dict[str, Any], zones: list[dict[str, Any]], networks: list[dict[str, Any]]) -> list[str]:
    if not isinstance(policy, dict):
        raise ValidationError("firewall policy must be a JSON object")
    origin = _policy_origin(policy)
    metadata = policy.get("metadata") if isinstance(policy.get("metadata"), dict) else {}
    if origin in POLICY_ORIGINS_PROTECTED or metadata.get("configurable") is False:
        raise PermissionError(f"refusing to mutate protected {origin or 'non-configurable'} firewall policy")
    if origin != "USER_DEFINED":
        raise ValidationError("firewall policy must explicitly be USER_DEFINED")
    action = policy.get("action")
    action_type = str(action.get("type") if isinstance(action, dict) else action or "").upper()
    if action_type not in POLICY_ACTIONS:
        raise ValidationError("firewall action must be ALLOW, BLOCK, or REJECT")
    zone_ids = {object_id(zone) for zone in zones}
    source = policy.get("source") if isinstance(policy.get("source"), dict) else {}
    destination = policy.get("destination") if isinstance(policy.get("destination"), dict) else {}
    for label, zone_id in (("source", source.get("zoneId")), ("destination", destination.get("zoneId"))):
        if not zone_id or str(zone_id) not in zone_ids:
            raise ValidationError(f"firewall {label} zone is missing or unknown")
    network_ids = {object_id(network) for network in networks}
    network_ids.update(str(item) for zone in zones for item in (zone.get("networkIds") or []))
    unknown_networks = _collect_named_refs(policy, "networkId", "networkIds") - network_ids
    if unknown_networks:
        raise ValidationError("firewall policy references an unknown network")
    index = policy.get("index", policy.get("order"))
    if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index <= 2147483647:
        raise ValidationError("firewall policy index/order must be an integer in controller range")
    scope = policy.get("ipProtocolScope") if isinstance(policy.get("ipProtocolScope"), dict) else {}
    ip_version = str(scope.get("ipVersion") or "IPV4_AND_IPV6").upper()
    if ip_version not in IP_VERSIONS:
        raise ValidationError("firewall policy has an unsupported IP version")
    protocol = scope.get("protocolFilter")
    if isinstance(protocol, str) and protocol.upper() not in {"ALL", "TCP", "UDP", "TCP_UDP", "ICMP", "ICMPV6", "GRE", "ESP", "AH"}:
        raise ValidationError("firewall policy has an unsupported protocol")
    states = policy.get("connectionStateFilter") or []
    if isinstance(states, dict):
        states = states.get("states") or states.get("items") or []
    if not isinstance(states, list) or any(str(state).upper() not in CONNECTION_STATES for state in states):
        raise ValidationError("firewall policy has an invalid connection-state filter")
    for address in _walk_address_values(policy):
        _validate_address(address)
    return ["USER_DEFINED/configurable origin", "known source and destination zones/networks",
            "valid action, addresses, protocol, connection state, IP version, and order"]


def _network_for_client(client: dict[str, Any], networks: list[dict[str, Any]]) -> dict[str, Any] | None:
    override = (client.get("virtual_network_override_id") or client.get("network_override_id") or
                client.get("networkOverrideId"))
    if client.get("virtual_network_override_enabled") is False:
        override = None
    network_id = (override or client.get("network_id") or client.get("networkId") or
                  client.get("last_connection_network_id") or client.get("lastConnectionNetworkId"))
    return next((network for network in networks if object_id(network) == str(network_id)), None)


def _network_identity(network: dict[str, Any]) -> dict[str, Any]:
    return {"id": object_id(network), "name": network.get("name"),
            "vlan": network.get("vlan", network.get("vlan_id"))}


def _fixed_ip_state(client: dict[str, Any], networks: list[dict[str, Any]]) -> dict[str, Any]:
    network = _network_for_client(client, networks) or {}
    return {
        "target_id": object_id(client),
        "mac": str(client.get("mac") or "").lower(),
        "network": _network_identity(network),
        "use_fixedip": client.get("use_fixedip") is True or client.get("fixedIpEnabled") is True,
        "fixed_ip": client.get("fixed_ip") or client.get("fixedIpAddress"),
    }


def validate_fixed_ip(ip_text: str, client: dict[str, Any], configured: list[dict[str, Any]],
                      active: list[dict[str, Any]], networks: list[dict[str, Any]]) -> tuple[list[str], str]:
    try:
        address = ipaddress.ip_address(ip_text)
    except ValueError as error:
        raise ValidationError("fixed IP is not a valid IP address") from error
    if address.version != 4:
        raise ValidationError("only fixed IPv4 is supported")
    network = _network_for_client(client, networks)
    subnet_text = (network or {}).get("ip_subnet") or (network or {}).get("subnet") or (network or {}).get("gatewayIp")
    try:
        subnet = ipaddress.ip_network(str(subnet_text), strict=False)
    except ValueError as error:
        raise ValidationError("client network has no usable authoritative subnet") from error
    if address not in subnet or address in {subnet.network_address, subnet.broadcast_address}:
        raise ValidationError("fixed IP does not belong to the client network subnet")
    gateway = str(subnet_text).split("/", 1)[0]
    if str(address) == gateway:
        raise ValidationError("fixed IP conflicts with the network gateway")
    mac = str(client.get("mac") or "").lower()
    target_id = object_id(client)
    for other in configured:
        if object_id(other) == target_id:
            continue
        other_ip = str(other.get("fixed_ip") or other.get("fixedIpAddress") or "")
        if other_ip == str(address):
            if other.get("use_fixedip") is True or other.get("fixedIpEnabled") is True:
                raise ValidationError("fixed IP conflicts with another reservation")
            raise ValidationError("fixed IP is claimed by another configured client")
    for other in active:
        if str(other.get("mac") or "").lower() != mac and str(other.get("ip") or other.get("ipAddress") or "") == str(address):
            raise ValidationError("fixed IP is currently assigned to another client")
    start = (network or {}).get("dhcpd_start") or (network or {}).get("dhcpStart")
    stop = (network or {}).get("dhcpd_stop") or (network or {}).get("dhcpStop")
    pool = "unknown"
    if start and stop:
        try:
            pool = "inside_dynamic_pool" if ipaddress.ip_address(str(start)) <= address <= ipaddress.ip_address(str(stop)) else "outside_dynamic_pool"
        except ValueError as error:
            raise ValidationError("network DHCP pool is malformed") from error
    return ["IPv4 belongs to client subnet and is not network/gateway/broadcast",
            "no conflicting reservation or active lease",
            f"DHCP pool relationship: {pool}", RESERVATION_SEMANTICS], pool


class GuardedMutator:
    def __init__(self, client: Any, *, site_id: str, internal_site: str,
                 env: dict[str, str] | None = None, snapshot_base: Path | None = None,
                 lock_path: Path | None = None, controller_host: str | None = None,
                 site_name: str = "unknown", network_version: str = "unknown",
                 identity_reader: Callable[[], ControllerIdentity] | None = None,
                 journal_base: Path | None = None):
        self.client = client
        self.site_id = site_id
        self.internal_site = internal_site
        self.env = dict(env or {})
        self.snapshot_base = snapshot_base or ROOT / "snapshots"
        self.lock_path = lock_path or ROOT / "snapshots" / ".mutation.lock"
        host = controller_host or str(getattr(client, "base", "") or "test-controller").removeprefix("https://").rstrip("/")
        if not host or not site_id or not internal_site or not network_version or network_version == "unknown":
            raise ValidationError("complete controller host, site identity, and UniFi Network version are required")
        if identity_reader is None:
            raise ValidationError("an authoritative controller/site identity reader is required")
        self.identity = ControllerIdentity(host, site_id, internal_site, site_name, network_version)
        self.identity_reader = identity_reader
        self.journal = OperationJournal(journal_base or ROOT / "operations")

    def _legacy(self, path: str) -> str:
        return f"/proxy/network/api/s/{self.internal_site}/{path}"

    def _official(self, path: str) -> str:
        return f"{INTEGRATION}/sites/{self.site_id}/{path}"

    def _url(self, endpoint: str) -> str:
        base = str(getattr(self.client, "base", "")).rstrip("/")
        return f"{base}{endpoint}" if base else endpoint

    @contextmanager
    def _single_mutation(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise MutationError("another mutation plan/apply operation is already in progress") from error
            yield

    def _get(self, endpoint: str) -> Any:
        try:
            optional = getattr(self.client, "get_optional", None)
            if optional:
                return optional(self._url(endpoint))
            return self.client.get(self._url(endpoint))
        except (SystemExit, Exception) as error:
            if isinstance(error, MutationError):
                raise
            raise StateMismatch("current-state GET failed") from error

    def _get_official_collection(self, path: str) -> list[dict[str, Any]]:
        """Fetch a complete Integration v1 collection without losing pagination."""
        endpoint = self._official(path)
        optional = getattr(self.client, "get_optional", None)
        if not optional:
            return _records(self._get(endpoint + "?offset=0&limit=200"))
        offset = 0
        limit = 200
        collected: list[dict[str, Any]] = []
        while True:
            try:
                page = optional(self._url(endpoint + f"?offset={offset}&limit={limit}"), unwrap=False)
            except (Exception, SystemExit) as error:
                raise StateMismatch("current-state GET failed") from error
            records = _records(page)
            collected.extend(records)
            if not isinstance(page, dict):
                break
            count = int(page.get("count", len(records)))
            total = int(page.get("totalCount", count))
            if offset + count >= total or count == 0:
                break
            offset += int(page.get("limit", limit) or limit)
        return collected

    def _write(self, method: str, endpoint: str, body: dict[str, Any] | None = None) -> Any:
        url = self._url(endpoint)
        try:
            guarded = getattr(self.client, "guarded_write", None)
            if guarded:
                return guarded(method, url, body)
            if method == "POST":
                return self.client.post(url, body)
            if method == "PUT":
                return self.client.put(url, body)
            if method == "DELETE":
                return self.client.delete(url)
            raise ValueError("unsupported mutation method")
        except (Exception, SystemExit) as error:
            if isinstance(error, MutationError):
                raise
            raise MutationError("controller write request failed; no raw response was emitted") from error

    def _snapshot(self, object_type: str, object_id_value: str, current: Any,
                  operation: str, proposed: Any, metadata: dict[str, Any] | None = None) -> Path:
        try:
            return create_snapshot("unifi-network", object_type, object_id_value, current,
                                   operation, proposed, self.snapshot_base, restorable=True,
                                   metadata=metadata, controller_identity=self.identity.as_dict())
        except SnapshotError as error:
            raise MutationError(str(error)) from error

    def _plan(self, operation: str, object_type: str, target: dict[str, Any], before: Any,
              after: Any, approved_state: Any, level: int, snapshot: Path,
              effects: list[str], validation: list[str], method: str, endpoint: str,
              rollback_path: str | None = None, *, approval_before: Any = _UNSET,
              approval_after: Any = _UNSET, approval_target: Any = _UNSET,
              approval_context: Any = None, precondition_state: Any = _UNSET) -> MutationPlan:
        if redact(before) != before or redact(after) != after:
            raise ValidationError("exact mutation diff contains sensitive fields and cannot be safely displayed")
        diff = json_diff(before, after)
        if not diff:
            raise ValidationError("proposed mutation makes no change")
        identity = self.identity.as_dict()
        before_fp = state_fingerprint(approved_state)
        after_fp = state_fingerprint(after)
        stable_before = before if approval_before is _UNSET else approval_before
        stable_after = after if approval_after is _UNSET else approval_after
        stable_target = target if approval_target is _UNSET else approval_target
        semantic_diff = json_diff(stable_before, stable_after)
        approval_material = {
            "controller_site": identity,
            "target_object_type": object_type,
            "target_identity": stable_target,
            "before": stable_before,
            "after": stable_after,
            "operation": operation,
            "semantic_diff": semantic_diff,
            "safety_level": level,
        }
        if approval_context is not None:
            approval_material["safety_context"] = approval_context
        if redact(approval_material) != approval_material:
            raise ValidationError("approval material contains sensitive fields and cannot be safely displayed")
        approval_fp = approval_fingerprint(approval_material)
        stable_precondition = approved_state if precondition_state is _UNSET else precondition_state
        precondition_fp = state_fingerprint(stable_precondition)
        operation_id = new_operation_id()
        timestamp = utc_now()
        record = self.journal.create({
            "operation_id": operation_id, "timestamp": timestamp,
            "controller_identity": identity, "command": operation,
            "target": redact(target), "before_state_fingerprint": before_fp,
            "after_state_fingerprint": after_fp, "snapshot_path": str(snapshot),
            "precondition_fingerprint": precondition_fp,
            "approval_fingerprint": approval_fp, "mutation_endpoint": endpoint,
            "mutation_method": method, "result": "PLANNED_NO_WRITE",
            "verification_result": None, "rollback_snapshot": str(snapshot),
            "rollback_attempted": False,
            "authoritative_write_count": 0,
        })
        return MutationPlan(
            operation_id=operation_id, timestamp=timestamp, controller_identity=identity,
            operation=operation, target_object_type=object_type, target_identity=target,
            current_state=before, proposed_state=after, diff=diff, safety_level=level,
            snapshot_path=str(snapshot), expected_generated_effects=effects,
            validation_steps=validation, rollback_path=rollback_path or str(snapshot),
            current_state_fingerprint=before_fp, proposed_state_fingerprint=after_fp,
            precondition_fingerprint=precondition_fp, approval_fingerprint=approval_fp,
            approval_token=approval_token(operation, target, approval_fp),
            mutation_method=method, mutation_endpoint=endpoint, operation_record=str(record),
            approved_state=approved_state, precondition_state=stable_precondition,
            approval_material=approval_material,
        )

    def _finish(self, plan: MutationPlan, *, dry_run: bool, approval: str | None,
                freshness: Callable[[], Any], write: Callable[[], Any],
                verify: Callable[[Any], dict[str, Any]],
                precondition: Callable[[Any], Any] | None = None,
                runtime_validate: Callable[[Any], None] | None = None) -> dict[str, Any]:
        if dry_run:
            return {"mode": "PLAN", "write_performed": False, "plan": plan.public()}
        try:
            MutationGate.authorize(plan, approval, self.env)
        except PermissionError:
            self.journal.update(Path(plan.operation_record), {"result": "REFUSED_AUTHORIZATION",
                                "completed_at": utc_now()})
            raise
        try:
            fresh_identity = self.identity_reader()
        except (Exception, SystemExit):
            self.journal.update(Path(plan.operation_record), {"result": "REFUSED_IDENTITY_RECHECK_FAILED",
                                "completed_at": utc_now()})
            raise StaleApprovalError("controller/site identity could not be re-established immediately before write")
        if fresh_identity != self.identity:
            self.journal.update(Path(plan.operation_record), {"result": "REFUSED_IDENTITY_MISMATCH",
                                "completed_at": utc_now()})
            raise StaleApprovalError("controller or site identity changed after planning; generate a new plan")
        try:
            fresh_state = freshness()
        except (Exception, SystemExit) as error:
            self.journal.update(Path(plan.operation_record), {"result": "REFUSED_FRESHNESS_RECHECK_FAILED",
                                "completed_at": utc_now()})
            raise StaleApprovalError("authoritative state could not be re-fetched immediately before write") from error
        fresh_precondition = precondition(fresh_state) if precondition else fresh_state
        if normalize_state(fresh_precondition) != normalize_state(plan.precondition_state):
            self.journal.update(Path(plan.operation_record), {"result": "REFUSED_STALE_APPROVAL",
                                "completed_at": utc_now(),
                                "observed_precondition_fingerprint": state_fingerprint(fresh_precondition)})
            raise StaleApprovalError("Approved state is stale: mutation preconditions changed. Generate a new plan and obtain new approval.")
        if runtime_validate:
            try:
                runtime_validate(fresh_state)
            except (MutationError, PermissionError) as error:
                self.journal.update(Path(plan.operation_record), {
                    "result": "REFUSED_RUNTIME_SAFETY_CHECK", "completed_at": utc_now(),
                    "runtime_safety_error": str(error),
                })
                raise
        write_count = 1
        self.journal.update(Path(plan.operation_record), {"result": "WRITE_ATTEMPTED",
                            "attempted_at": utc_now(), "authoritative_write_count": write_count,
                            "rollback_attempted": plan.operation == "port-forward.restore"})
        try:
            response = write()
        except (Exception, SystemExit) as error:
            try:
                verification = verify(None)
            except (Exception, SystemExit):
                verification = {"verified": False, "reconciliation": "authoritative refetch failed"}
            reconciled = bool(verification.get("verified"))
            result_name = "RECONCILED_APPLIED_AFTER_AMBIGUOUS_RESPONSE" if reconciled else "AMBIGUOUS_REQUIRES_REVIEW"
            completion = self._completion(plan, write_count, verification, result_name,
                                          ambiguous=True)
            self.journal.update(Path(plan.operation_record), {"result": result_name,
                                "completed_at": utc_now(), "verification_result": redact(verification),
                                "write_response_ambiguous": True})
            if reconciled:
                return completion
            raise AmbiguousWriteError(
                "write outcome is ambiguous; no retry occurred; authoritative state did not conclusively reconcile; new approval is required",
                completion) from error
        verification = verify(response)
        result_name = "APPLIED_VERIFIED" if verification.get("verified") else "APPLIED_VERIFICATION_FAILED"
        completion = self._completion(plan, write_count, verification, result_name,
                                      ambiguous=False)
        self.journal.update(Path(plan.operation_record), {"result": result_name,
                            "completed_at": utc_now(), "verification_result": redact(verification),
                            "write_response_ambiguous": False})
        if not verification.get("verified"):
            raise VerificationError("write completed but post-write verification failed; no secondary mutation was attempted",
                                    completion)
        return completion

    @staticmethod
    def _completion(plan: MutationPlan, write_count: int, verification: dict[str, Any],
                    result_name: str, *, ambiguous: bool) -> dict[str, Any]:
        safe_verification = redact(verification)
        return {"mode": result_name, "write_performed": True, "plan": plan.public(),
                "verification": safe_verification,
                "completion_block": {"Mutation attempted": True,
                                     "Authoritative write count": write_count,
                                     "Ambiguous write response": ambiguous,
                                     "Verification": safe_verification,
                                     "Unrelated-state check": safe_verification.get("unrelated_state_unchanged", safe_verification.get("unrelated_forwards_unchanged")),
                                     "Rollback available": plan.rollback_path,
                                     "Operation record": plan.operation_record}}

    def port_forward_delete(self, identifier: str, *, expected: dict[str, Any] | None = None,
                            dry_run: bool = True, approval: str | None = None) -> dict[str, Any]:
        with self._single_mutation():
            collection_endpoint = self._legacy("rest/portforward")
            item_endpoint = f"{collection_endpoint}/{identifier}"
            def read_state() -> dict[str, Any]:
                records = _records(self._get(collection_endpoint))
                item = _records(self._get(item_endpoint))
                return {"target": item[0] if item else None, "port_forwards": records,
                        "firewall_policies": self._get_official_collection("firewall/policies"),
                        "firewall_zones": self._get_official_collection("firewall/zones"),
                        "forwarding_status": _records(self._get(self._legacy("stat/portforward")))}

            approved_state = read_state()
            current_records = approved_state["port_forwards"]
            target = approved_state["target"]
            if not target or object_id(target) != identifier:
                raise StateMismatch("target port forward was not returned by its authoritative GET")
            if _find(current_records, identifier) is None:
                raise StateMismatch("target port forward is absent from the authoritative collection")
            verify_expected(target, expected)
            validation = _validate_port_forward(target)
            policies_before = approved_state["firewall_policies"]
            zones_before = approved_state["firewall_zones"]
            status_before = approved_state["forwarding_status"]
            snapshot = self._snapshot("port-forward", identifier, target, "delete port forward", None,
                                      {"api_family": "legacy/private", "endpoint": item_endpoint})
            related_policy_before = _related(policies_before, target)
            related_directions = [_policy_direction(item, zones_before) for item in related_policy_before]
            related_status_before = _related(status_before, target)
            rollback_command = f"python3 scripts/mutate.py port-forward restore --snapshot {snapshot} --plan"
            def port_forward_precondition(state: dict[str, Any]) -> dict[str, Any]:
                return {
                    "target": _strip_keys(state.get("target"), VOLATILE_KEYS),
                    "port_forwards": _stable_collection(state["port_forwards"]),
                    "firewall_policies": _stable_collection(state["firewall_policies"], ordered=True),
                    "firewall_zones": _stable_collection(state["firewall_zones"]),
                }

            stable_target = _strip_keys(target, VOLATILE_KEYS)
            plan = self._plan("port-forward.delete", "port-forward",
                              {"id": identifier, "name": target.get("name")},
                              target, None, approved_state, 3, snapshot,
                              [f"{len(related_policy_before)} related official firewall policy object(s) should disappear ({', '.join(related_directions) or 'none observed'})",
                               f"{len(related_status_before)} related forwarding-status object(s) should disappear",
                               "controller-derived objects are never directly edited"],
                              validation + ["official policies and forwarding status were fetched",
                                            "semantic duplicates, unrelated forwards/policies, and unexpected additions will be checked"],
                              "DELETE", item_endpoint, rollback_command,
                              approval_before=stable_target, approval_after=None,
                              approval_target={"id": identifier},
                              precondition_state=port_forward_precondition(approved_state))
            unrelated_before = {object_id(item): item for item in current_records if object_id(item) != identifier}
            related_policy_ids = {object_id(item) for item in related_policy_before}
            unrelated_generated_before = {object_id(item): normalize_state(item) for item in policies_before
                                          if object_id(item) not in related_policy_ids and
                                          _policy_origin(item) in POLICY_ORIGINS_PROTECTED}
            before_ids = {object_id(item) for item in current_records}

            def verify(_: Any) -> dict[str, Any]:
                forwards_after = _records(self._get(collection_endpoint))
                policies_after = self._get_official_collection("firewall/policies")
                status_after = _records(self._get(self._legacy("stat/portforward")))
                unrelated_after = {object_id(item): item for item in forwards_after if object_id(item) != identifier}
                policies_gone = not _related(policies_after, target)
                status_gone = not _related(status_after, target)
                target_absent = _find(forwards_after, identifier) is None
                semantic_duplicate = any(_port_forward_signature(item) == _port_forward_signature(target)
                                         for item in forwards_after)
                unrelated_unchanged = normalize_state(unrelated_after) == normalize_state(unrelated_before)
                unexpected_ids = sorted({object_id(item) for item in forwards_after} - (before_ids - {identifier}))
                unrelated_generated_after = {object_id(item): normalize_state(item) for item in policies_after
                                             if object_id(item) not in related_policy_ids and
                                             _policy_origin(item) in POLICY_ORIGINS_PROTECTED}
                generated_unchanged = unrelated_generated_after == unrelated_generated_before
                verified = (target_absent and not semantic_duplicate and unrelated_unchanged and
                            not unexpected_ids and policies_gone and generated_unchanged and status_gone)
                return {"verified": verified, "target_disappeared": target_absent,
                        "semantic_equivalent_absent": not semantic_duplicate,
                        "unrelated_forwards_unchanged": unrelated_unchanged,
                        "unrelated_generated_policies_unchanged": generated_unchanged,
                        "unrelated_state_unchanged": unrelated_unchanged and generated_unchanged,
                        "unexpected_new_port_forwards": unexpected_ids,
                        "generated_policy_disappeared": policies_gone,
                        "forwarding_status_disappeared": status_gone,
                        "related_policy_count_before": len(related_policy_before),
                        "related_status_count_before": len(related_status_before),
                        "rollback": rollback_command}
            return self._finish(plan, dry_run=dry_run, approval=approval,
                                freshness=read_state,
                                write=lambda: self._write("DELETE", item_endpoint), verify=verify,
                                precondition=port_forward_precondition)

    def port_forward_restore(self, snapshot_path: Path, *, dry_run: bool = True,
                             approval: str | None = None) -> dict[str, Any]:
        with self._single_mutation():
            _manifest, original = load_snapshot(snapshot_path, expected_type="port-forward",
                                                expected_identity=self.identity.as_dict())
            validation = _validate_port_forward(original)
            collection_endpoint = self._legacy("rest/portforward")
            def read_state() -> dict[str, Any]:
                fresh_manifest, fresh_original = load_snapshot(snapshot_path, expected_type="port-forward",
                                                               expected_identity=self.identity.as_dict())
                return {"port_forwards": _records(self._get(collection_endpoint)),
                        "firewall_policies": self._get_official_collection("firewall/policies"),
                        "firewall_zones": self._get_official_collection("firewall/zones"),
                        "forwarding_status": _records(self._get(self._legacy("stat/portforward"))),
                        "source_snapshot_sha256": fresh_manifest["snapshot_sha256"],
                        "source_snapshot_state_fingerprint": state_fingerprint(fresh_original)}

            approved_state = read_state()
            current = approved_state["port_forwards"]
            old_id = object_id(original)
            if _find(current, old_id):
                raise StateMismatch("port forward already exists; restore would duplicate it")
            policies_before = approved_state["firewall_policies"]
            status_before = approved_state["forwarding_status"]
            proposed = _strip_keys(copy.deepcopy(original), IDENTITY_KEYS | VOLATILE_KEYS)
            if any(_port_forward_signature(item) == proposed for item in current):
                raise StateMismatch("a semantically equivalent port forward already exists; restore would duplicate it")
            safety_snapshot = self._snapshot("port-forward-collection", old_id, current,
                                             "pre-restore port-forward collection", proposed,
                                             {"source_snapshot": str(snapshot_path)})
            target = {"source_snapshot": str(snapshot_path), "original_id": old_id,
                      "name": original.get("name")}
            def restore_precondition(state: dict[str, Any]) -> dict[str, Any]:
                return {
                    "port_forwards": _stable_collection(state["port_forwards"]),
                    "firewall_policies": _stable_collection(state["firewall_policies"], ordered=True),
                    "firewall_zones": _stable_collection(state["firewall_zones"]),
                    "source_snapshot_sha256": state["source_snapshot_sha256"],
                    "source_snapshot_state_fingerprint": state["source_snapshot_state_fingerprint"],
                }

            restore_context = {
                "target_absent": True,
                "semantic_duplicate_absent": True,
                "source_snapshot_sha256": approved_state["source_snapshot_sha256"],
                "source_snapshot_state_fingerprint": approved_state["source_snapshot_state_fingerprint"],
            }
            plan = self._plan("port-forward.restore", "port-forward", target,
                              approved_state, proposed, approved_state, 3, safety_snapshot,
                              ["controller assigns an id and regenerates firewall policy/status objects"],
                              validation + ["source snapshot checksum and controller/site identity are valid",
                                            "no existing object has the original id",
                                            "semantic restoration and unrelated state will be checked"],
                              "POST", collection_endpoint,
                              f"pre-restore collection snapshot: {safety_snapshot}",
                              approval_before=None, approval_after=proposed,
                              approval_target={"original_id": old_id,
                                               "source_snapshot_sha256": approved_state["source_snapshot_sha256"]},
                              approval_context=restore_context,
                              precondition_state=restore_precondition(approved_state))
            before_forwards = {object_id(item): normalize_state(item) for item in current}
            before_policy_ids = {object_id(item) for item in policies_before}
            unrelated_policies_before = {object_id(item): normalize_state(item) for item in policies_before}

            def verify(response: Any) -> dict[str, Any]:
                forwards_after = _records(self._get(collection_endpoint))
                response_records = _records(response)
                response_id = object_id(response_records[0]) if response_records else ""
                restored = _find(forwards_after, response_id) if response_id else None
                if restored is None:
                    restored = next((item for item in forwards_after if _port_forward_signature(item) == proposed), None)
                policies_after = self._get_official_collection("firewall/policies")
                status_after = _records(self._get(self._legacy("stat/portforward")))
                policy_reappeared = bool(_related(policies_after, restored or original)) and len(policies_after) >= len(policies_before)
                restored_policy_directions = [_policy_direction(item, approved_state["firewall_zones"])
                                              for item in _related(policies_after, restored or original)]
                status_reappeared = bool(_related(status_after, restored or original)) and len(status_after) >= len(status_before)
                new_id = object_id(restored) if restored else None
                semantics_match = bool(restored and _contains(_semantics(restored), proposed))
                semantic_matches = [item for item in forwards_after if _port_forward_signature(item) == proposed]
                unrelated_after = {object_id(item): normalize_state(item) for item in forwards_after
                                   if object_id(item) != new_id}
                unrelated_forwards_unchanged = unrelated_after == before_forwards
                new_policy_ids = {object_id(item) for item in policies_after} - before_policy_ids
                related_policy_after_ids = {object_id(item) for item in _related(policies_after, restored or original)}
                unexpected_new_policy_ids = sorted(new_policy_ids - related_policy_after_ids)
                unrelated_policies_after = {object_id(item): normalize_state(item) for item in policies_after
                                            if object_id(item) not in new_policy_ids}
                unrelated_policies_unchanged = unrelated_policies_after == unrelated_policies_before
                verified = (bool(restored) and semantics_match and len(semantic_matches) == 1 and
                            policy_reappeared and status_reappeared and unrelated_forwards_unchanged and
                            unrelated_policies_unchanged and not unexpected_new_policy_ids)
                return {"verified": verified,
                        "restored": bool(restored), "semantics_match": semantics_match,
                        "semantic_restoration": semantics_match and len(semantic_matches) == 1,
                        "generated_policy_reappeared": policy_reappeared,
                        "generated_policy_restoration": policy_reappeared,
                        "generated_policy_directions": restored_policy_directions,
                        "forwarding_status_reappeared": status_reappeared,
                        "unrelated_forwards_unchanged": unrelated_forwards_unchanged,
                        "unrelated_generated_policies_unchanged": unrelated_policies_unchanged,
                        "unrelated_state_unchanged": unrelated_forwards_unchanged and unrelated_policies_unchanged,
                        "unexpected_new_policy_ids": unexpected_new_policy_ids,
                        "original_id": old_id, "new_id": new_id, "id_changed": bool(new_id and new_id != old_id),
                        "automatic_rollback": False}

            def validate_restore_runtime(state: dict[str, Any]) -> None:
                if _find(state["port_forwards"], old_id):
                    raise StateMismatch("port forward already exists; restore would duplicate it")
                if any(_port_forward_signature(item) == proposed for item in state["port_forwards"]):
                    raise StateMismatch("a semantically equivalent port forward already exists; restore would duplicate it")

            return self._finish(plan, dry_run=dry_run, approval=approval,
                                freshness=read_state,
                                write=lambda: self._write("POST", collection_endpoint, proposed), verify=verify,
                                precondition=restore_precondition,
                                runtime_validate=validate_restore_runtime)

    def fixed_ip_change(self, mac: str, address: str | None, *, dry_run: bool = True,
                        approval: str | None = None) -> dict[str, Any]:
        with self._single_mutation():
            configured_endpoint = self._legacy("rest/user")
            normalized_mac = mac.lower()
            def read_state() -> dict[str, Any]:
                configured_records = _records(self._get(configured_endpoint))
                target_record = next((item for item in configured_records
                                      if str(item.get("mac") or "").lower() == normalized_mac), None)
                item_records = _records(self._get(f"{configured_endpoint}/{object_id(target_record)}")) if target_record else []
                return {"target": item_records[0] if item_records else target_record,
                        "configured_clients": configured_records,
                        "active_clients": _records(self._get(self._legacy("stat/sta"))),
                        "networks": _records(self._get(self._legacy("rest/networkconf")))}

            approved_state = read_state()
            configured = approved_state["configured_clients"]
            active = approved_state["active_clients"]
            networks = approved_state["networks"]
            current = approved_state["target"]
            if current is None or not object_id(current):
                raise StateMismatch("client has no authoritative configurable rest/user object; creation is intentionally unsupported")
            if str(current.get("mac") or "").lower() != normalized_mac:
                raise StateMismatch("authoritative client identity does not match the requested MAC")
            network = _network_for_client(current, networks)
            if network is None:
                raise ValidationError("client network/VLAN association cannot be established authoritatively")
            proposed = copy.deepcopy(current)
            validation = ["authoritative client configuration was fetched and bound by MAC",
                          "network/VLAN association is authoritative and will be checked again immediately before write"]
            pool = "not_applicable"
            if address:
                address = str(ipaddress.ip_address(address))
                extra, pool = validate_fixed_ip(address, current, configured, active, networks)
                validation.extend(extra)
                proposed["use_fixedip"] = True
                proposed["fixed_ip"] = address
            else:
                proposed["use_fixedip"] = False
                proposed.pop("fixed_ip", None)
                proposed.pop("fixedIpAddress", None)
                validation.append("fixed-IP fields cleared while unrelated client settings are preserved")
            identifier = object_id(current)
            item_endpoint = f"{configured_endpoint}/{identifier}"
            snapshot = self._snapshot("client-configuration", identifier, current,
                                      "set fixed IP" if address else "remove fixed IP", proposed,
                                      {"api_family": "legacy/private", "endpoint": item_endpoint})
            operation = "client.fixed-ip.set" if address else "client.fixed-ip.remove"
            network_identity = _network_identity(network)
            approval_before = _fixed_ip_state(current, networks)
            approval_after = _fixed_ip_state(proposed, networks)
            approval_target = {"id": identifier, "mac": normalized_mac,
                               "network": network_identity}
            def fixed_ip_precondition(state: dict[str, Any]) -> dict[str, Any]:
                fresh_target = state.get("target")
                if not isinstance(fresh_target, dict):
                    return {"target_id": None}
                return {
                    "put_source": _strip_keys(fresh_target, VOLATILE_KEYS),
                    "mutation_state": _fixed_ip_state(fresh_target, state["networks"]),
                }

            plan = self._plan(operation, "client-configuration",
                              {"id": identifier, "mac": normalized_mac, "name": current.get("name"),
                               "network": network_identity},
                              current, proposed, approved_state, 3, snapshot,
                              ["DHCP reservation is updated; a lease renewal may be required", f"DHCP pool relationship: {pool}"],
                              validation, "PUT", item_endpoint,
                              f"restore client object from {snapshot} with a separately approved mutation",
                              approval_before=approval_before, approval_after=approval_after,
                              approval_target=approval_target,
                              precondition_state=fixed_ip_precondition(approved_state))

            write_source = {"before": current, "after": proposed}

            def validate_runtime(state: dict[str, Any]) -> None:
                fresh_target = state.get("target")
                if not isinstance(fresh_target, dict) or object_id(fresh_target) != identifier:
                    raise StateMismatch("target configured client no longer exists")
                if str(fresh_target.get("mac") or "").lower() != normalized_mac:
                    raise StateMismatch("target configured-client MAC changed")
                fresh_network = _network_for_client(fresh_target, state["networks"])
                if fresh_network is None or object_id(fresh_network) != object_id(network):
                    raise StateMismatch("target configured client moved to a different network")
                if address:
                    validate_fixed_ip(address, fresh_target, state["configured_clients"],
                                      state["active_clients"], state["networks"])
                fresh_proposed = copy.deepcopy(fresh_target)
                if address:
                    fresh_proposed["use_fixedip"] = True
                    fresh_proposed["fixed_ip"] = address
                else:
                    fresh_proposed["use_fixedip"] = False
                    fresh_proposed.pop("fixed_ip", None)
                    fresh_proposed.pop("fixedIpAddress", None)
                write_source.update({"before": fresh_target, "after": fresh_proposed})

            def verify(_: Any) -> dict[str, Any]:
                after = _records(self._get(item_endpoint))
                updated = after[0] if after else None
                expected_enabled = bool(address)
                actual_enabled = bool(updated and (updated.get("use_fixedip") is True or updated.get("fixedIpEnabled") is True))
                actual_ip = (updated or {}).get("fixed_ip") or (updated or {}).get("fixedIpAddress")
                identity_matches = bool(updated and str(updated.get("mac") or "").lower() == normalized_mac and
                                        object_id(_network_for_client(updated, networks) or {}) == object_id(network))
                preserved = bool(updated and all(updated.get(key) == value for key, value in write_source["before"].items()
                                                  if key not in {"use_fixedip", "fixed_ip", "fixedIpEnabled", "fixedIpAddress"}))
                matches = actual_enabled == expected_enabled and (not address or str(actual_ip) == address)
                return {"verified": bool(updated) and matches and preserved and identity_matches,
                        "fixed_ip_matches": matches, "unrelated_settings_preserved": preserved,
                        "client_mac_and_network_match": identity_matches,
                        "unrelated_state_unchanged": preserved,
                        "lease_renewal_may_be_required": True,
                        "rollback": f"restore client object from {snapshot} with a separately approved mutation"}
            return self._finish(plan, dry_run=dry_run, approval=approval,
                                freshness=read_state,
                                write=lambda: self._write("PUT", item_endpoint, write_source["after"]), verify=verify,
                                precondition=fixed_ip_precondition,
                                runtime_validate=validate_runtime)

    def firewall_policy_create(self, policy: dict[str, Any], *, dry_run: bool = True,
                               approval: str | None = None) -> dict[str, Any]:
        return self._firewall_policy("create", None, policy, dry_run=dry_run, approval=approval)

    def firewall_policy_update(self, identifier: str, changes: dict[str, Any], *, dry_run: bool = True,
                               approval: str | None = None) -> dict[str, Any]:
        return self._firewall_policy("update", identifier, changes, dry_run=dry_run, approval=approval)

    def firewall_policy_delete(self, identifier: str, *, dry_run: bool = True,
                               approval: str | None = None) -> dict[str, Any]:
        return self._firewall_policy("delete", identifier, None, dry_run=dry_run, approval=approval)

    def _firewall_policy(self, action: str, identifier: str | None, payload: dict[str, Any] | None,
                         *, dry_run: bool, approval: str | None) -> dict[str, Any]:
        with self._single_mutation():
            collection_endpoint = self._official("firewall/policies")
            item_endpoint = f"{collection_endpoint}/{identifier}" if identifier else collection_endpoint

            def read_state() -> dict[str, Any]:
                policies_now = self._get_official_collection("firewall/policies")
                item = _records(self._get(item_endpoint)) if identifier else []
                return {"target": item[0] if item else None, "policies": policies_now,
                        "zones": self._get_official_collection("firewall/zones"),
                        "networks": self._get_official_collection("networks")}

            approved_state = read_state()
            policies = approved_state["policies"]
            zones = approved_state["zones"]
            networks = approved_state["networks"]
            current = approved_state["target"]
            if identifier:
                if not current or object_id(current) != identifier:
                    raise StateMismatch("target firewall policy was not returned by its authoritative GET")
                validate_policy(current, zones, networks)
            if action == "create":
                proposed = _strip_keys(copy.deepcopy(payload), IDENTITY_KEYS | VOLATILE_KEYS)
                before = approved_state
                validation = validate_policy(proposed, zones, networks)
                snapshot_value = _policy_snapshot(policies, proposed, zones)
                snapshot_type = "firewall-policy-collection"
                snapshot_id = "pre-create"
            elif action == "update":
                if not isinstance(payload, dict):
                    raise ValidationError("firewall update requires a JSON object of changes")
                proposed = _deep_merge(current, payload)
                before = current
                validation = validate_policy(proposed, zones, networks)
                snapshot_value = _policy_snapshot(policies, current, zones)
                snapshot_type = "firewall-policy"
                snapshot_id = identifier or "unknown"
            else:
                validate_policy(current or {}, zones, networks)
                proposed = None
                before = current
                validation = ["target is USER_DEFINED and configurable", "related zones/networks were fetched"]
                snapshot_value = _policy_snapshot(policies, current, zones)
                snapshot_type = "firewall-policy"
                snapshot_id = identifier or "unknown"
            snapshot = self._snapshot(snapshot_type, snapshot_id, snapshot_value,
                                      f"{action} USER_DEFINED firewall policy", proposed,
                                      {"api_family": "official/integration-v1", "endpoint": item_endpoint})
            target = {"id": identifier, "name": (current or proposed or {}).get("name"), "origin": "USER_DEFINED"}
            operation = f"firewall-policy.{action}"
            method = {"create": "POST", "update": "PUT", "delete": "DELETE"}[action]
            def firewall_precondition(state: dict[str, Any]) -> dict[str, Any]:
                return {
                    "target": _strip_keys(state.get("target"), VOLATILE_KEYS),
                    "policies": _stable_collection(state["policies"], ordered=True),
                    "zones": _stable_collection(state["zones"]),
                    "networks": _stable_collection(state["networks"]),
                }

            stable_firewall_state = firewall_precondition(approved_state)
            stable_firewall_before = _strip_keys(current, VOLATILE_KEYS) if current else None
            plan = self._plan(operation, "firewall-policy", target, before, proposed,
                              approved_state, 2, snapshot,
                              ["only the authoritative USER_DEFINED policy changes; normalized semantics are refetched"],
                              validation + ["complete policy order and neighboring policies are snapshotted",
                                            "unrelated policy ordering will be verified"],
                              method, item_endpoint,
                              f"restore USER_DEFINED policy state from {snapshot} with separate approval",
                              approval_before=stable_firewall_before,
                              approval_after=_strip_keys(proposed, VOLATILE_KEYS),
                              approval_target={"id": identifier, "origin": "USER_DEFINED"},
                              approval_context=stable_firewall_state,
                              precondition_state=stable_firewall_state)
            before_order = _policy_order_signature(policies, {identifier} if identifier else set())

            def write() -> Any:
                if action == "create":
                    return self._write("POST", collection_endpoint, proposed)
                if action == "update":
                    return self._write("PUT", item_endpoint, proposed)
                return self._write("DELETE", item_endpoint)

            def verify(response: Any) -> dict[str, Any]:
                after = self._get_official_collection("firewall/policies")
                if action == "delete":
                    gone = _find(after, identifier or "") is None
                    order_unchanged = _policy_order_signature(after) == before_order
                    return {"verified": gone and order_unchanged, "target_disappeared": gone,
                            "normalized_semantics_match": gone,
                            "unrelated_policy_order_unchanged": order_unchanged,
                            "unrelated_state_unchanged": order_unchanged,
                            "rollback": f"restore USER_DEFINED policy from {snapshot} with separate approval"}
                response_records = _records(response)
                resulting_id = object_id(response_records[0]) if response_records else (identifier or "")
                actual = _find(after, resulting_id)
                if actual is None and action == "create":
                    actual = next((item for item in after if _contains(_semantics(item), _semantics(proposed))), None)
                semantics_match = bool(actual and _contains(_semantics(actual), _semantics(proposed)))
                resulting_id = object_id(actual) if actual else resulting_id
                order_unchanged = _policy_order_signature(after, {resulting_id}) == before_order
                return {"verified": semantics_match and _policy_origin(actual or {}) == "USER_DEFINED" and order_unchanged,
                        "resulting_id": object_id(actual) if actual else None,
                        "normalized_semantics_match": semantics_match, "origin": _policy_origin(actual or {}),
                        "unrelated_policy_order_unchanged": order_unchanged,
                        "unrelated_state_unchanged": order_unchanged}
            return self._finish(plan, dry_run=dry_run, approval=approval,
                                freshness=read_state, write=write, verify=verify,
                                precondition=firewall_precondition)
