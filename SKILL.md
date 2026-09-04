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
5. Prefer local analysis: `python3 scripts/audit.py exposure --input inventory.json`, `python3 scripts/audit.py firewall --input inventory.json`, or `python3 scripts/audit.py all --input inventory.json --report`.
6. Use `--json` or `--json-output FILE` for machine-readable findings and correlated port-forward assessments.
7. Distinguish evidence as `measured`, `reported`, `inferred`, `correlated`, or `not_available`. Describe uncertain rules as “candidate for review,” never “unused.”

The auditor correlates objects but does not externally scan WAN reachability, prove that
a configured forward is reachable, inspect downstream reverse-proxy mappings, or modify
the controller. Port numbers and object names are supporting evidence rather than proof.

The expanded inventory plan must show application-version discovery, site discovery,
every site-scoped GET, API family, purpose, and pagination behavior before live
collection. Prefer official Integration v1. Mark unsupported optional datasets
unavailable without terminating collection or exposing raw controller error bodies.

## Resources

- Read `references/homelab-topology.md` for topology or port analysis.
- Read `references/security-policy.md` and `references/audit-benchmarks.md` for audits.
- Read `references/desired-state.yaml` for drift/segmentation comparisons.
- Read `references/upstream-notes.md` for API coverage, licensing, and upstream decisions.
- Use `scripts/udm.py` only as the preserved low-level client. Prefer the guarded scripts for normal work.
- Use `scripts/snapshot.py`, `scripts/rollback.py`, and `scripts/verify_network.py` for change planning and verification.
- Use `scripts/mutate.py ... --plan` for guarded mutation plans. A later live invocation requires the exact emitted `--approve` token as well as write enablement; rollback is separately planned and approved.
- Treat approval identity, authoritative preconditions, and runtime conflict checks separately. Tokens bind stable semantic mutation material; every apply still refetches relevant state and reruns conflicts immediately before its one write.
- Never call `UDMClient.post`, `put`, `delete`, `guarded_write`, or another low-level mutation method directly. Supported writes must originate in `mutationlib.py` through `scripts/mutate.py`; ambiguous writes are reconciled by GET and never retried automatically.

Never put credentials, raw sensitive inventory, reports, or snapshots into Git.
