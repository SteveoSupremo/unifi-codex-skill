# UniFi Codex Skill

A read-only-first OpenAI Codex Agent Skill for inventorying, auditing, troubleshooting, and carefully planning changes to a UniFi home network. It derives from the MIT-licensed [`dlewis7444/unifi-claude-skill`](https://github.com/dlewis7444/unifi-claude-skill); `scripts/udm.py` remains the upstream low-level client.

## Safety model

Live writes are disabled by default. Level 0 reads are permitted after credential checks; operational actions require an exact request; configuration and critical-infrastructure changes require current-state discovery, snapshot, full diff, validation, explicit approval, one logical mutation, refetch, network verification, and a report.

`UNIFI_ENABLE_WRITES=I_UNDERSTAND_THIS_CHANGES_MY_NETWORK` is necessary for a live write but is **not authorization**. Every operation must first run with `--plan`; the plan emits an approval token bound to the operation, target, current state, and proposed state. A separate invocation must supply that exact token with `--approve`. If current state changes, the token changes. Rollback is another mutation and requires its own plan and approval. The low-level `udm.py` CLI refuses all writes and non-GET raw calls.

Plans are additionally bound to the UDM host, site UUID/internal reference/name, and
Network version. Immediately before its single authoritative write, the command
refetches identity and complete approved state; any drift invalidates approval. Writes
are never retried automatically after an ambiguous transport result. The framework
instead performs read-only reconciliation and requires new approval if the outcome is
not conclusive.

## Requirements and installation

Python 3.10+ is sufficient; runtime code uses the standard library. Develop from this checkout and install with a symlink:

```bash
mkdir -p ~/.agents/skills
ln -s /absolute/path/unifi-codex-skill ~/.agents/skills/unifi
python3 /path/to/skill-creator/scripts/quick_validate.py /absolute/path/unifi-codex-skill
```

Invoke with `$unifi`, or ask Codex to audit UniFi/network health, exposure, firewall policy, Wi-Fi, performance, or drift.

## API key and read-only first run

Generate a local key in UniFi Network's Control Plane/Integrations settings (the exact UI varies by Network release), then:

```bash
cp .env.example .env
chmod 600 .env
$EDITOR .env
git check-ignore .env
git status --short
python3 -m unittest discover -s tests -v
python3 scripts/inventory.py --plan
python3 scripts/inventory.py --output inventory.json
python3 scripts/audit.py all --input inventory.json --report
```

The collector uses `X-API-Key`. Local controller certificates are often self-signed; upstream `udm.py` disables verification, a documented limitation. Never commit `.env`, inventories, reports, or snapshots.

The inventory plan identifies the installed Network application version first, discovers
the site, and lists every GET before collection. Official Integration v1 is preferred
for connected clients, firewall zones/policies, Wi-Fi broadcasts, WAN interfaces, VPN
servers, and site-to-site tunnels. Optional UPnP forwarding status and IDS/IPS settings
are explicitly labeled as version-sensitive legacy GETs because the documented official
catalog has no equivalent. Unsupported optional endpoints are recorded as unavailable
without aborting collection; official collections are paginated using GET only.

Fixed-IP configuration is different from a connected client's observed lease. The
collector correlates official/observed client data with the version-sensitive
legacy/private `rest/user` configured-client collection. `fixed_ip_states` reports the
MAC identity, configured fixed-IP flag/address, current lease, network/VLAN, any exposed
network override, and whether authoritative configured state was available. Output is
sanitized; no reservation is created by inventory.

## Commands

```bash
python3 scripts/safety.py status
python3 scripts/audit.py firewall --input inventory.json
python3 scripts/audit.py exposure --input inventory.json
python3 scripts/audit.py all --input inventory.json --report
python3 scripts/audit.py exposure --input inventory.json --json
python3 scripts/audit.py exposure --input inventory.json --json-output exposure.json
python3 scripts/audit.py health --input inventory.json
python3 scripts/audit.py performance --input inventory.json
python3 scripts/verify_network.py --host unifi.local
python3 scripts/snapshot.py --target controller --type firewall-rule --id ID --input object.json --reason "planned change"
python3 scripts/rollback.py snapshots/.../object.json --current current.json --dry-run
```

## Guarded mutation commands

All commands below contact the controller with GET requests and create a local,
Git-ignored snapshot. Commands ending in `--plan` do not write:

```bash
python3 scripts/mutate.py port-forward delete --id ID --expect 'name="Expected name"' --plan
python3 scripts/mutate.py port-forward delete --id ID --expect 'name="Expected name"' --approve APPROVE-...

python3 scripts/mutate.py port-forward restore --snapshot snapshots/TIMESTAMP --plan
python3 scripts/mutate.py port-forward restore --snapshot snapshots/TIMESTAMP --approve APPROVE-...

python3 scripts/mutate.py client fixed-ip set --mac 00:11:22:33:44:55 --ip 192.168.7.60 --plan
python3 scripts/mutate.py client fixed-ip remove --mac 00:11:22:33:44:55 --plan

python3 scripts/mutate.py firewall policy create --input policy.json --plan
python3 scripts/mutate.py firewall policy update --id POLICY_ID --input changes.json --plan
python3 scripts/mutate.py firewall policy delete --id POLICY_ID --plan
```

Only after reviewing an unchanged plan should an operator explicitly enable writes and
rerun one command with its exact token:

```bash
export UNIFI_ENABLE_WRITES=I_UNDERSTAND_THIS_CHANGES_MY_NETWORK
python3 scripts/mutate.py ... --approve APPROVE-...
```

Plan output includes full approval/current/proposed fingerprints and ends with a
`safety_block` containing `NO WRITE HAS OCCURRED.` Actual execution emits a matching
`completion_block`. Immutable rollback snapshots are mode 0600, checksummed, and bound
to controller/site identity. Sanitized operation records are written under
`operations/`; they contain fingerprints and verification results but never API keys,
passwords, or approval tokens.

Port-forward deletion and restore use the authoritative, version-sensitive
legacy/private `/proxy/network/api/s/{site}/rest/portforward` endpoint. They refetch
official Integration v1 firewall policies and legacy forwarding status to verify
controller-generated effects; generated policies are never directly edited.

Fixed-IP discovery and mutation use version-sensitive legacy/private `rest/user`,
`stat/sta`, and `rest/networkconf` endpoints because the official connected-client API
is observational and does not authoritatively expose reservation configuration on the
tested Network generation. A fixed-IP change requires an existing configured-client
object and uses full-object GET/deep-copy/PUT semantics. Address validation includes the
associated subnet, gateway/network/broadcast exclusions, active leases, reservations,
and DHCP pool relationship.

UniFi treats Fixed IP Address as a DHCP reservation. Both inside- and outside-pool
addresses are handled without imposing a guessed exclusion rule; the relationship is
reported while subnet, gateway, active lease, reservation, MAC, and network/VLAN
identity checks remain mandatory.

USER_DEFINED firewall policy create/update/delete uses official Integration v1
`/sites/{siteId}/firewall/policies` with related zone and network GETs. Request schema
support is controller-version-specific; use the local Network > Integrations API
documentation. SYSTEM_DEFINED, DERIVED, unknown-origin, and non-configurable policies
are refused. Policy validation covers zone/network references, addresses, action,
protocol, connection state, IP version, and order.

The Version 2 auditor correlates port forwards with collected device/client identity,
network/VLAN membership, protected roles, documented topology, service-port hints, and
related policy evidence. Port numbers and friendly names are supporting evidence, not
proof. Reports include audit coverage and important unknowns, and classify recommended
actions as `KEEP / VERIFY`, `REVIEW`, `HARDEN`, `CANDIDATE FOR REMOVAL`, or
`UNKNOWN — INVESTIGATE`; passive evidence never produces an automatic removal.

The auditor does not externally scan the WAN, inspect application authentication or
TLS, prove that a configured forward is Internet-reachable, or modify the controller.
Machine-readable JSON contains findings plus complete port-forward assessments and
always reports `live_mutation: false`.

When official firewall zones and policies are collected, reports also include an
effective segmentation matrix, normalized policy findings, explicit port-forward policy
correlation, VPN/management-access context, IDS/IPS configured posture, and reconciled
UPnP/dynamic-forwarding evidence. Coverage distinguishes analyzed, partially analyzed,
empty, unavailable, and unsupported datasets.

Generic `rollback.py` remains a plan-only diff helper. Supported port-forward rollback
is provided by `mutate.py port-forward restore`; it never executes automatically and
requires a separate snapshot, diff, write gate, and approval token.

## Architecture and API limitations

Official local Integration API endpoints are preferred. The official API expands across sites, devices, clients, networks, Wi-Fi, firewall policies/zones, ACLs, DNS policies, traffic matching lists, VPN/WAN and switching, but exact local coverage is controller-version-specific. Legacy statistics, port forwards, older firewall objects, DPI, events, routes, and some VPN information may require undocumented/private endpoints used by upstream `udm.py`; treat them as version-sensitive.

The HP ProCurve 2810-24G is outside UniFi control and outside this mutation framework.
The skill must not claim it can modify or fully inventory those physical ports.

## Git and upstream workflow

This installation uses HTTPS for both remotes:

```text
origin   = https://github.com/SteveoSupremo/unifi-codex-skill.git
upstream = https://github.com/dlewis7444/unifi-claude-skill.git
```

Configure or verify them with:

```bash
git remote set-url origin https://github.com/SteveoSupremo/unifi-codex-skill.git
git remote set-url upstream https://github.com/dlewis7444/unifi-claude-skill.git
git remote -v
git fetch upstream
git log HEAD..upstream/master
git diff HEAD...upstream/master -- scripts/udm.py
```

SSH URLs are an optional alternative when SSH authentication is configured; HTTPS is the current setup. Use the actual default branch reported by GitHub. Do not force-push. See `references/upstream-notes.md` for adopted concepts and scope decisions.

## Troubleshooting

- `401/403`: verify the local Integration API key and its permissions without printing it.
- TLS errors: install/trust the controller certificate where possible; never disable verification silently.
- `404`: confirm Network version and endpoint family in the controller's local API docs.
- Empty data: verify site discovery; do not assume the site is named `default`.

## License and attribution

MIT; see `LICENSE`. Original work copyright remains with its authors. Architectural ideas from `sirkirby/unifi-mcp` and `enuno/unifi-mcp-server` are acknowledged; their code was not copied into this implementation.
