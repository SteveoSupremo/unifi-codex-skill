# Research and upstream notes

Upstream `dlewis7444/unifi-claude-skill` (MIT) supplies the compact `udm.py` client and command coverage. It mixes official Integration v1 reads with private legacy and v2 endpoints, disables TLS verification, exits from transport code, exposes an unrestricted raw mutation escape hatch, and offers destructive commands without approval gates. This fork preserves that file for comparison but routes normal operation through guarded tools.

Ideas adopted from `sirkirby/unifi-mcp`: health/audit separation, transparent findings, protected permission boundaries, preview-before-mutation, snapshots, post-change verification, and configuration history concepts. Its broad manager/server architecture was intentionally not copied.

Ideas adopted from `enuno/unifi-mcp-server`: local API-key operation, API-family grouping, typed/sanitized boundaries, and broader official Integration API awareness. Its MCP server, cloud/multi-controller, Protect, webhook, database, and agent-to-agent scope are unnecessary for this skill.

Skills.rest material was treated as design inspiration only; no catalog code was incorporated. Current Codex conventions use concise `SKILL.md`, `agents/openai.yaml`, and user-level `.agents/skills` installation. Official local UniFi API documentation is controller-version-specific under Network > Integrations; official endpoints should be preferred, with private endpoints clearly marked version-sensitive.

The last sanitized inventory reports Network 10.5.67 and UniFi OS 5.1.26. Public
Ubiquiti documentation confirms Integration v1 GET collections for application info,
sites, clients, Wi-Fi broadcasts, firewall zones/policies, WAN interfaces, VPN servers,
and site-to-site VPN tunnels. Controller-local Network > Integrations documentation is
still authoritative for 10.5.67. No documented official UPnP or IDS/IPS settings
collection was found, so optional legacy GETs are labeled and degrade to unavailable.

The guarded mutation layer is intentionally outside `udm.py`. The upstream CLI's
write and non-GET raw branches are refused in this fork, while a small sanitized
`guarded_write` transport remains available to `mutationlib.py` after its central gate.
Port-forward and configured-client writes remain legacy/private and version-sensitive.
Firewall-policy mutation paths use official Integration v1, but the controller-local
Network > Integrations schema is authoritative for accepted bodies and methods.
The official Network 10.1.84 OpenAPI contract confirms that firewall-policy CREATE uses
the create/update DTO and that `id`, `index`, and `metadata` belong only to the response
model. Network 10.5.67 exposes the same collection locally; serialization remains
allowlisted and version-sensitive.
