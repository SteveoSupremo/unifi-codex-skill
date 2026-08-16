---
name: unifi
description: Administer, inventory, audit, harden, troubleshoot, and optimize a UniFi home network with read-only-first safeguards. Use for UniFi clients, devices, VLANs, networks, Wi-Fi, firewall or traffic policies, Internet exposure, port forwards, VPN, routes, WAN/DNS/DHCP health, performance, drift, snapshots, rollback planning, or any requested network configuration change.
---

# UniFi Network Administration

Operate from this skill directory. Treat the controller as production infrastructure.

## Absolute safety boundary

- Default to Level 0/read-only. Run `python3 scripts/safety.py status` before controller work.
- Never perform a live mutation unless the user explicitly requests the exact change and `UNIFI_ENABLE_WRITES=I_UNDERSTAND_THIS_CHANGES_MY_NETWORK` is set.
- Never infer approval from an audit finding. Never use `udm.py raw` with POST, PUT, PATCH, or DELETE.
- For Level 2/3 work, read `references/mutation-safety.md` and `references/protected-resources.yaml` first. Refuse ambiguous Level 3 requests.
- Apply one logical change at a time: discover, GET full object, snapshot, deep-copy, minimal edit, diff, validate, show user, obtain explicit approval, apply, GET again, compare, verify, report.
- Keep the HP ProCurve outside the control boundary. It is not UniFi-managed.

## Read-only workflow

1. Confirm `.env` is ignored with `git check-ignore .env`; never display secrets.
2. Run mocked tests before first live contact.
3. Preview reads with `python3 scripts/inventory.py --plan`.
4. Use `python3 scripts/inventory.py` for a sanitized inventory or `python3 scripts/audit.py <network|firewall|exposure|performance|wifi|health|all> [--report]`.
5. Distinguish evidence as `measured`, `reported`, `inferred`, or `not_available`. Describe uncertain rules as “candidate for review,” never “unused.”

## Resources

- Read `references/homelab-topology.md` for topology or port analysis.
- Read `references/security-policy.md` and `references/audit-benchmarks.md` for audits.
- Read `references/desired-state.yaml` for drift/segmentation comparisons.
- Read `references/upstream-notes.md` for API coverage, licensing, and upstream decisions.
- Use `scripts/udm.py` only as the preserved low-level client. Prefer the guarded scripts for normal work.
- Use `scripts/snapshot.py`, `scripts/rollback.py`, and `scripts/verify_network.py` for change planning and verification.

Never put credentials, raw sensitive inventory, reports, or snapshots into Git.
