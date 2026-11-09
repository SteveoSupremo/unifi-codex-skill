"""Pinned official Integration v1 DNS contract; no mutation transport here.

Reviewed public OpenAPI: Network 10.1.84, 10.5.67, 10.6.106, 10.6.109.
See references/dns-management.md for provenance and intentional restrictions.
"""
from __future__ import annotations

import copy
import ipaddress
import re
import uuid
from typing import Any, Callable

SUPPORTED_VERSIONS = frozenset({"10.1.84", "10.5.67", "10.6.106", "10.6.109"})
REQUEST_FIELDS = frozenset({"type", "enabled", "domain", "ipv4Address", "ttlSeconds"})
RECORD_FIELDS = REQUEST_FIELDS | {"id", "metadata"}
RECORD_TYPES = {"A_RECORD", "AAAA_RECORD", "CNAME_RECORD", "MX_RECORD", "TXT_RECORD",
                "SRV_RECORD", "FORWARD_DOMAIN"}
ORIGINS = {"USER_DEFINED", "SYSTEM_DEFINED", "DERIVED", "ORCHESTRATED"}


class DnsContractError(ValueError):
    """Sanitized incompatibility, validation or conflict error."""


def require_version(version: str) -> None:
    if version not in SUPPORTED_VERSIONS:
        # Only echo a bounded version identifier, never arbitrary controller text.
        detected = version if isinstance(version, str) and re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:[-+][A-Za-z0-9.-]{1,32})?", version) else "unknown/unrecognized"
        supported = ", ".join(sorted(SUPPORTED_VERSIONS, key=lambda v: tuple(map(int, v.split(".")))))
        raise DnsContractError(
            f"unsupported Network version for DNS: {detected}; reviewed versions: {supported}. "
            "Review this build's official OpenAPI DNS contract and update the skill's "
            "scripts/dns_api.py allowlist and tests; see references/dns-management.md."
        )


def record_id(value: Any) -> str:
    if not isinstance(value, str):
        raise DnsContractError("DNS policy ID must be a UUID")
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except ValueError as error:
        raise DnsContractError("DNS policy ID must be a canonical UUID") from error
    return value


def domain_name(value: Any, *, observed: bool = False) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise DnsContractError("DNS name must be a nonempty hostname without whitespace")
    name = value.lower().removesuffix(".")
    if observed and name.startswith("*."):
        name = name[2:]
        wildcard = True
    else:
        wildcard = False
    # API limit is 127; ASCII LDH hostnames are an intentional narrower subset.
    pattern = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?" if observed else r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(value) > 127 or not name.isascii() or not all(
        re.fullmatch(pattern, label)
        for label in name.split(".")
    ):
        raise DnsContractError("unsupported DNS name: ASCII host labels, at most 127 characters; wildcards/IDNs are not managed")
    return ("*." if wildcard else "") + name


def validate_a(record: Any, *, response: bool = False, writable: bool = False) -> dict:
    if not isinstance(record, dict) or not REQUEST_FIELDS <= record.keys():
        raise DnsContractError("unknown or incomplete Host A schema")
    if record["type"] != "A_RECORD" or not isinstance(record["enabled"], bool):
        raise DnsContractError("only explicit IPv4 A_RECORD policies with boolean enabled are managed")
    if not isinstance(record["ttlSeconds"], int) or isinstance(record["ttlSeconds"], bool) or not 0 <= record["ttlSeconds"] <= 86400:
        raise DnsContractError("ttlSeconds must be an integer from 0 to 86400")
    name = domain_name(record["domain"], observed=response and not writable)
    if not isinstance(record["ipv4Address"], str):
        raise DnsContractError("ipv4Address must be an IPv4 string")
    try:
        address = ipaddress.IPv4Address(record["ipv4Address"])
    except ipaddress.AddressValueError as error:
        raise DnsContractError("ipv4Address must be a valid IPv4 address") from error
    allowed = RECORD_FIELDS if response else REQUEST_FIELDS
    if not set(record) <= allowed:
        raise DnsContractError("unknown Host A fields; refusing a possibly lossy replacement")
    if response:
        if not {"id", "metadata"} <= record.keys():
            raise DnsContractError("Host A response lacks ID or origin metadata")
        record_id(record["id"])
        metadata = record["metadata"]
        if not isinstance(metadata, dict) or not isinstance(metadata.get("origin"), str) or metadata["origin"] not in ORIGINS:
            raise DnsContractError("unknown DNS policy origin/schema")
        if writable and (metadata != {"origin": "USER_DEFINED"}):
            raise DnsContractError("protected, non-user or unknown DNS record metadata")
    return {"type": "A_RECORD", "enabled": record["enabled"], "domain": name,
            "ipv4Address": str(address), "ttlSeconds": record["ttlSeconds"]}


def validate_collection(records: Any) -> list[dict]:
    if not isinstance(records, list):
        raise DnsContractError("DNS collection must be an array")
    ids = set()
    for record in records:
        if not isinstance(record, dict) or not {"id", "type", "enabled", "metadata", "domain"} <= record.keys():
            raise DnsContractError("unknown DNS collection record schema")
        identifier = record_id(record["id"])
        if identifier in ids:
            raise DnsContractError("ambiguous duplicate DNS policy IDs")
        ids.add(identifier)
        metadata = record["metadata"]
        if not isinstance(record["type"], str) or record["type"] not in RECORD_TYPES or not isinstance(record["enabled"], bool) or not isinstance(metadata, dict) or not isinstance(metadata.get("origin"), str) or metadata["origin"] not in ORIGINS:
            raise DnsContractError("unknown DNS policy type, origin or enablement schema")
        required = {"AAAA_RECORD": {"ipv6Address", "ttlSeconds"},
                    "CNAME_RECORD": {"targetDomain", "ttlSeconds"},
                    "MX_RECORD": {"mailServerDomain", "priority"}, "TXT_RECORD": {"text"},
                    "SRV_RECORD": {"port", "priority", "protocol", "serverDomain", "service", "weight"},
                    "FORWARD_DOMAIN": {"ipAddress"}}.get(record["type"], set())
        if not required <= record.keys():
            raise DnsContractError("incomplete DNS record subtype schema")
        domain_name(record["domain"], observed=True)
        if record["type"] == "A_RECORD":
            validate_a(record, response=True)
    return records


def fetch_records(get: Callable[[str], Any], endpoint: str) -> list[dict]:
    """Fail closed on truncated, inconsistent or non-progressing pagination."""
    offset = 0
    records: list[dict] = []
    expected_total = None
    while True:
        page = get(f"{endpoint}?offset={offset}&limit=200")
        if not isinstance(page, dict) or not {"data", "offset", "count", "limit", "totalCount"} <= page.keys():
            raise DnsContractError("unknown DNS pagination envelope")
        if not isinstance(page["data"], list) or any(type(page[k]) is not int for k in ("offset", "count", "limit", "totalCount")):
            raise DnsContractError("malformed DNS pagination")
        count, total = page["count"], page["totalCount"]
        if page["offset"] != offset or count != len(page["data"]) or not 1 <= page["limit"] <= 200 or count > page["limit"] or total < offset + count or total > 10000:
            raise DnsContractError("inconsistent or oversized DNS collection")
        if expected_total is not None and total != expected_total:
            raise DnsContractError("DNS collection changed during pagination")
        expected_total = total
        records.extend(page["data"])
        if offset + count == total:
            return copy.deepcopy(validate_collection(records))
        if count == 0:
            raise DnsContractError("incomplete DNS collection; no pagination progress")
        offset += count


def check_conflicts(records: list[dict], name: str, *, exclude_id: str | None = None) -> list[dict]:
    """Conservative single-owner policy, including disabled and wildcard entries."""
    exact = []
    for record in records:
        if record["id"] == exclude_id:
            continue
        other = domain_name(record["domain"], observed=True)
        if other == name:
            exact.append(record)
        elif other.startswith("*.") and name.endswith(other[1:]):
            raise DnsContractError("conflicting wildcard DNS record covers this hostname")
        elif record["type"] in {"CNAME_RECORD", "FORWARD_DOMAIN"} and name.endswith("." + other):
            raise DnsContractError("conflicting ancestor alias or forwarding policy")
    return exact
