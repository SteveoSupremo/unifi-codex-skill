# Audit data gaps

Version 2 does not expand the live collector. The current inventory is sufficient for
basic contextual exposure analysis, and all existing collection calls are read-only
GET requests. These datasets would improve later audits.

| Priority | Dataset / endpoint purpose | API family | Method | Why it matters | Version sensitivity |
| --- | --- | --- | --- | --- | --- |
| Needed now | None | — | — | Existing port forwards, networks, devices, legacy firewall rules, traffic rules, and health support Version 2 basics. | — |
| Useful later | Active and known clients | Prefer official local Integration API clients endpoint; legacy `/stat/sta` only if required | GET | Correlates forwarded IPs with hostname, MAC, network, and identity. | Official coverage and fields vary by Network release; legacy endpoint is private. |
| Useful later | Firewall zones and policies | Official local Integration API firewall zone/policy endpoints | GET | Establishes zone association and newer effective policy beyond empty legacy rule families. | Endpoint availability and schemas are release-sensitive. |
| Useful later | WLAN configuration | Official local Integration API Wi-Fi endpoints | GET | Enables authentication, guest, and SSID-to-network checks. | Release-sensitive feature fields. |
| Useful later | WAN interfaces | Official local Integration API WAN endpoints where exposed | GET | Distinguishes interfaces, addressing, failover, and listener scope. | Local official coverage varies. |
| Useful later | VPN configuration | Official local Integration API VPN endpoints; documented local API first | GET | Separates deliberate VPN listeners and evaluates administrative posture. | Product/version dependent. |
| Useful later | UPnP mappings | Legacy/private operational endpoint if no official equivalent exists | GET | Detects dynamic exposure absent from static port-forward objects. | Highly version-sensitive; validate against local docs. |
| Useful later | IDS/IPS settings and status | Official settings/status endpoints where available | GET | Provides compensating-control and signature-health evidence. | Schema and licensing/features vary. |
| Useful later | Switching and uplink state | Official device/port endpoints where available | GET | Improves topology and path analysis for UniFi-managed equipment only. | Does not cover the external HP ProCurve. |

Before adding any endpoint, preview the exact request and verify that its method is GET.
Never infer permission for live discovery from this document.

## Current sanitized field map

The successful inventory established these material fields without requiring raw-object
output:

- Port forwards: `name`, `enabled`, `proto`, `dst_port`, `fwd`, `fwd_port`, `src`,
  `src_limiting_enabled`, `destination_ip`, `destination_ips`, `pfwd_interface`.
- Networks: `_id`, `name`, `vlan`, `ip_subnet`, `purpose`, `networkgroup`,
  `firewall_zone_id`, `network_isolation_enabled`.
- UniFi devices: `_id`, `name`, `hostname`, `ip`, `lan_ip`, `mac`, `model`, `type`,
  `connection_network_name`, `mgmt_network_id` (availability varies by device).
- Health: top-level `health` and `sysinfo` within the collected status object.
- Firewall/traffic rules: the present inventory contains empty datasets, so Version 2
  accepts common legacy and newer field aliases but makes no claim about fields absent
  from reported objects.
