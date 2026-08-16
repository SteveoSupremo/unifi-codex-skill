# Research and upstream notes

Upstream `dlewis7444/unifi-claude-skill` (MIT) supplies the compact `udm.py` client and command coverage. It mixes official Integration v1 reads with private legacy and v2 endpoints, disables TLS verification, exits from transport code, exposes an unrestricted raw mutation escape hatch, and offers destructive commands without approval gates. This fork preserves that file for comparison but routes normal operation through guarded tools.

Ideas adopted from `sirkirby/unifi-mcp`: health/audit separation, transparent findings, protected permission boundaries, preview-before-mutation, snapshots, post-change verification, and configuration history concepts. Its broad manager/server architecture was intentionally not copied.

Ideas adopted from `enuno/unifi-mcp-server`: local API-key operation, API-family grouping, typed/sanitized boundaries, and broader official Integration API awareness. Its MCP server, cloud/multi-controller, Protect, webhook, database, and agent-to-agent scope are unnecessary for this skill.

Skills.rest material was treated as design inspiration only; no catalog code was incorporated. Current Codex conventions use concise `SKILL.md`, `agents/openai.yaml`, and user-level `.agents/skills` installation. Official local UniFi API documentation is controller-version-specific under Network > Integrations; official endpoints should be preferred, with private endpoints clearly marked version-sensitive.
