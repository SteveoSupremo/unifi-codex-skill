# Incident diagnosis and improvement validation

## Establish the observation window

Record the affected device, application/symptom, incident start/end and timezone.
Use known context first; ask only for missing information that changes the investigation.
Separate incident-time events, later snapshots, and configuration evidence. The collector
records UTC `collection_started_at`/`collection_finished_at`; requests are sequential,
not an atomic snapshot. Older files without these fields have unknown observation time.
Report generation time and filesystem modification time are not measurement timestamps.

Start with an existing inventory for offline analysis:

```bash
python3 scripts/audit.py wifi --input inventory/current.json
python3 scripts/audit.py health --input inventory/current.json
python3 scripts/audit.py performance --input inventory/current.json --json
```

For a new capture follow SKILL.md's read-only workflow, preview the collection plan,
then save to a distinct ignored inventory filename so a later sample preserves the
baseline. Do not treat a saved snapshot as current merely because it is called `current`.

## Interpret the automated checks

All metrics below come from existing legacy/private, version-sensitive GET datasets.
The checks use the reported fields directly; missing or malformed values reduce
coverage rather than becoming zero or a healthy result.

| Scope | Input | Interpretation |
| --- | --- | --- |
| `wifi` | `devices[].radio_table_stats[].cu_total`, `tx_retries_pct` | Flag utilization ≥80% and retries ≥20% for investigation. |
| `health` | `status.health[].status`, `devices[].system-stats.cpu` / `mem` | Flag non-healthy subsystem reports and CPU/memory ≥90%. |
| `performance`, `all` | Both groups above | Correlate candidates across radio and device health. |

These thresholds are local review heuristics, not Ubiquiti limits or performance
guarantees. They neither authorize tuning nor establish that load was sustained.
Repeat samples during symptoms and compare with a quiet baseline. Averaging windows
are controller-defined; do not calculate a retry percentage from cumulative counters
without known counter semantics and a sampling interval. Counters can reset on reboot.

## Follow the failing path

- **Connection state:** Use the current connected-client dataset or current station
  telemetry to establish presence at capture time. `stat/alluser`, last-disconnect,
  and historical signal records are historical context. Absence from a partial list
  does not prove disconnection. An associated Wi-Fi client can still have stalled
  application traffic.
- **Radio:** Correlate AP, radio/band, channel, client signal, utilization, retries,
  and event time. High utilization does not identify the interference source. Strong
  signal does not rule out contention. Investigate drops on different bands separately.
  Use AirView history and Environment observations for a measured channel choice.
- **Path and services:** Distinguish client-to-gateway, DNS resolution, Internet access,
  and the affected application. Compare a wired client if available. Check actual
  VLAN/network assignment and reservation/lease agreement. A healthy WAN subsystem
  does not prove DNS, DHCP, casting/discovery, inter-VLAN access, or application health.
  Do not infer ProCurve port state from the UniFi uplink; that switch is externally managed.
- **Events:** Correlate disconnect/reconnect sequences, AP uptime changes, channel/radar
  events, and WAN events with the requested window. State pagination, retention and
  missing-client limits. No recorded event does not exclude an unlogged fault.
  Network 10.x system-log queries in `udm.py events` use private POST requests;
  they are not part of the GET-only inventory. Do not route them through raw writes
  or assume the GET plan covers them. Use existing event captures or a controller UI
  export when a supported guarded read path is unavailable.

## Propose and verify improvements

Rank proposals by supporting evidence, expected benefit, disruption and uncertainty.
For each proposed change identify the affected clients/SSID/VLAN, baseline metric,
success criterion, and rollback. Preserve intended isolation when suggesting Ethernet
or a different band/SSID. Check device compatibility before proposing roaming/security
changes. Firmware suggestions require current stable release notes and model support.

RF scans, Channel AI, reconnects, restarts, speed tests and configuration changes are
active operations; they do not follow automatically from permission to inspect data.
Use the skill's applicable authorization boundary and disclose service impact.
After an authorized change, compare the same client/application and a comparable load
window; record observed improvement separately from an inferred explanation.

## Sources and remaining gaps

Ubiquiti's [WiFi Troubleshooting Guide](https://help.ui.com/hc/en-us/articles/32064585817495-WiFi-Troubleshooting-Guide)
supports reviewing signal, utilization, retries and historical airtime together.
Its [connectivity guidance](https://help.ui.com/hc/en-us/articles/221029967-Optimizing-WiFi-Connectivity-and-Reducing-Latency)
recommends 20 MHz width for 2.4 GHz; wider-band settings depend on the environment.
Reviewed 2026-10-18. These sources do not define this skill's numeric review thresholds.

The automated audit does not yet correlate event timelines, collect current detailed
station statistics, compare multiple snapshots, probe DNS/DHCP or measure uplink error
rates. State those gaps explicitly when they prevent diagnosis; do not substitute
zero findings for proof of health.
