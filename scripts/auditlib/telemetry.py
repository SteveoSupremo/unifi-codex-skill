"""Offline analysis of reported, version-sensitive health/device statistics."""
from __future__ import annotations

import math
from typing import Any

from unifi_common import Finding

# Investigation thresholds, not vendor limits or automatic tuning targets.
THRESHOLDS = {"cpu": 90, "mem": 90, "cu_total": 80, "tx_retries_pct": 20}


def _records(value: Any) -> list[dict]:
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []


def _percent(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        number = float(value)
    except ValueError:
        return None
    return number if math.isfinite(number) and 0 <= number <= 100 else None


def analyze_telemetry(data: dict[str, Any], scope: str) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    observations: list[dict] = []
    coverage: dict[str, str] = {}
    raw_statuses = data.get("collection_status")
    statuses = raw_statuses if isinstance(raw_statuses, dict) else {}
    limitations = [
        "Reported snapshot values do not establish sustained load or the cause of an earlier incident.",
        "Controller health does not test client DNS, DHCP, VLAN reachability, or application delivery.",
        "Historical client records and last-disconnect timestamps do not establish current connection state.",
    ]

    def status(dataset: str) -> str | None:
        entry = statuses.get(dataset)
        return entry.get("status") if isinstance(entry, dict) else None

    def metric(entity: str, key: str, value: Any, source: str, label: str, advice: str) -> bool:
        number = _percent(value)
        if number is None:
            return False
        observations.append({"entity": entity, "metric": key, "value": number,
                             "unit": "percent", "source": source, "evidence_type": "reported"})
        if number >= THRESHOLDS[key]:
            findings.append(Finding(
                "medium", "Telemetry", f"{entity}: elevated {label}",
                f"{source}.{key}={number:g}%; review threshold={THRESHOLDS[key]}%.",
                "This sample may indicate contention or load; persistence and user impact are unproven.",
                "medium", advice, "reported", False, "INVESTIGATE",
            ))
        return True

    def record_coverage(label: str, dataset: str, valid: int, expected: int) -> None:
        state = status(dataset)
        if state == "unavailable":
            coverage[label] = "unavailable"
        elif not valid:
            coverage[label] = "no usable telemetry"
        elif state == "partial" or valid < expected:
            coverage[label] = "partially analyzed"
        else:
            coverage[label] = "collected and analyzed"
        if coverage[label] != "collected and analyzed":
            limitations.append(f"{label}: {coverage[label]}; missing or invalid values are not healthy readings.")

    devices = _records(data.get("devices")) if status("devices") != "unavailable" else []
    if scope in ("all", "performance", "health"):
        raw_status = data.get("status")
        health = _records(raw_status.get("health")) if isinstance(raw_status, dict) else []
        if status("health") == "unavailable":
            health = []
        valid = 0
        for row in health:
            subsystem, state = row.get("subsystem"), row.get("status")
            if not isinstance(subsystem, str) or not isinstance(state, str):
                continue
            normalized = state.lower()
            if normalized in ("", "unknown", "unavailable"):
                continue
            valid += 1
            observations.append({"entity": subsystem, "metric": "status", "value": state,
                                 "source": "status.health", "evidence_type": "reported"})
            if normalized not in ("ok", "healthy", "disabled"):
                findings.append(Finding(
                    "medium", "Telemetry", f"{subsystem}: controller reports {state}",
                    f"status.health subsystem={subsystem}, status={state}.",
                    "A controller subsystem reports a condition requiring investigation.",
                    "medium", "Correlate with incident-time events and a client connectivity check before changing configuration.",
                    "reported", False, "INVESTIGATE",
                ))
        record_coverage("Subsystem health", "health", valid, max(1, len(health)))
        valid = 0
        for index, device in enumerate(devices):
            name = str(device.get("name") or device.get("model") or f"device {index + 1}")
            stats = device.get("system-stats")
            stats = stats if isinstance(stats, dict) else {}
            for key, label in (("cpu", "CPU usage"), ("mem", "memory usage")):
                valid += metric(name, key, stats.get(key), "devices.system-stats", label,
                                "Repeat the sample during the symptom and compare device load and uptime with a quiet baseline.")
        record_coverage("Device CPU/memory", "devices", valid, max(1, len(devices) * 2))

    if scope in ("all", "performance", "wifi"):
        valid = expected = 0
        for index, device in enumerate(devices):
            radios = _records(device.get("radio_table_stats"))
            if not radios and device.get("type") == "uap":
                expected += 2
            for radio_index, radio in enumerate(radios):
                expected += 2
                name = str(device.get("name") or device.get("model") or f"device {index + 1}")
                entity = f"{name} / {radio.get('name') or radio.get('radio') or radio_index + 1} / channel {radio.get('channel', 'unknown')}"
                valid += metric(entity, "cu_total", radio.get("cu_total"), "devices.radio_table_stats",
                                "channel utilization",
                                "Compare AirView history and nearby channel observations during the symptom. Assess moving capable clients to Ethernet/5 GHz while preserving VLAN isolation; choose channel changes only from local measurements.")
                valid += metric(entity, "tx_retries_pct", radio.get("tx_retries_pct"), "devices.radio_table_stats",
                                "transmit retries",
                                "Correlate retry percentage with client signal, channel utilization, and incident-time disconnects. Do not infer interference or change roaming settings from retries alone.")
        record_coverage("Radio utilization/retries", "devices", valid, max(1, expected))
        limitations.append("Radio averaging windows are controller-defined; cumulative retry counters are not treated as rates.")

    started = data.get("collection_started_at")
    finished = data.get("collection_finished_at")
    if not started or not finished:
        limitations.append("Collection timestamps are unavailable; report generation time is not the observation time.")
    if any(value != "collected and analyzed" for value in coverage.values()):
        findings.append(Finding(
            "informational", "Telemetry", "Telemetry coverage incomplete",
            "; ".join(f"{key}: {value}" for key, value in coverage.items()),
            "Missing measurements prevent a complete assessment; no threshold finding does not establish health.",
            "high", "Collect a timestamped inventory and obtain missing incident-time metrics from the controller UI or a supported read endpoint.",
            "not_available", False, "INVESTIGATE",
        ))
    return findings, {"collection_started_at": started, "collection_finished_at": finished,
                      "coverage": coverage, "observations": observations,
                      "review_thresholds_percent": dict(THRESHOLDS), "limitations": limitations}
