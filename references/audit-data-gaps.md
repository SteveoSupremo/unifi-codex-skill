# Audit data gaps

The expanded collector implements the major Version 2 gaps with GET-only requests. The
expanded plan has not been contacted against the controller and requires approval first.

| Priority | Dataset / endpoint purpose | API family | Method | Why it matters | Version sensitivity |
| --- | --- | --- | --- | --- | --- |
| Implemented, pending approval | Connected clients | `/proxy/network/integration/v1/sites/{siteId}/clients` | Official Integration v1 GET | Correlates forwarded IPs with active client identity. | Paginated; local 10.5.67 docs remain authoritative. |
| Implemented, pending approval | Firewall zones and policies | `.../firewall/zones`, `.../firewall/policies` | Official Integration v1 GET | Establishes zone association and newer effective policy. | Schemas are release-sensitive. |
| Implemented, pending approval | Wi-Fi broadcasts | `.../wifi/broadcasts` | Official Integration v1 GET | Enables SSID/network/security checks. | Security detail varies by release. |
| Implemented, pending approval | WAN interfaces | `.../wans` | Official Integration v1 GET | Distinguishes interface definitions and listener scope. | Overview fields may be limited. |
| Implemented, pending approval | VPN state | `.../vpn/servers`, `.../vpn/site-to-site-tunnels` | Official Integration v1 GET | Separates deliberate VPN listeners and tunnel posture. | Product/version dependent. |
| Implemented, optional | UPnP/forwarding status | `/proxy/network/api/s/{site}/stat/portforward` | Legacy/private GET | May expose runtime/configured forwarding entries including UPnP. | Highly version-sensitive; unavailable is acceptable. |
| Implemented, optional | IDS/IPS settings | `/proxy/network/api/s/{site}/rest/setting/ips` | Legacy/private GET | Provides configured threat-management posture. | Undocumented and version-sensitive; unavailable is acceptable. |
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
