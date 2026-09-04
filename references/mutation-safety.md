# Mutation safety

## Permission levels

Level 0 reads are allowed after credential safeguards. Level 1 operational actions
require an exact request. Level 2 configuration requires current-state GET, snapshot,
full proposed diff, validation, explicit approval, one change, refetch, verification,
and report. Level 3 covers WAN, gateway/management, DHCP/DNS, routing, native
VLAN/trunk, server and VPN administration; refuse casual or ambiguous requests.

The HP ProCurve is outside this control boundary at every level.

## Central write gate

Every normal live mutation goes through `scripts/mutate.py` and the central gate in
`scripts/mutationlib.py`. Immediately before the one transport write, the gate checks:

1. `UNIFI_ENABLE_WRITES=I_UNDERSTAND_THIS_CHANGES_MY_NETWORK` is exact.
2. `--approve` contains the token bound to this operation, target, current object, and
   proposed object. The token comes from a previous matching `--plan`.
3. The current-state GET succeeded and expected identity fields matched.
4. A complete restorable snapshot exists. Planning stops if sensitive fields would
   have to be redacted from that snapshot.
5. The exact before/after diff is non-empty and validation succeeded.
6. The plan contains exactly one logical mutation and holds the mutation lock.

The approval fingerprint is deterministic and identifies one semantic mutation. It
covers controller/site/Network identity, target object type and stable identity,
operation-specific authoritative BEFORE fields, requested AFTER fields, semantic diff,
and safety level. It deliberately excludes snapshots and operation IDs, collection
times, lease age/timestamps, connected-client freshness, runtime telemetry, unrelated
client fields, and semantically irrelevant dictionary/list ordering. Repeating the same
plan against the same mutation-relevant BEFORE state therefore emits the same token.
A relevant BEFORE/AFTER field, semantic diff, controller, site, version, target, or
safety level change produces a different token; static approvals such as `--approve
yes` are invalid.

Approval identity, preconditions, and runtime conflict checks are separate. Each plan
records an approval fingerprint and a precondition fingerprint. The precondition
fingerprint covers authoritative mutation-relevant BEFORE state. Runtime conflict
checks use fresh controller observations but do not become approval identity merely
because their telemetry timestamps or lease age changed.

Environment enablement is necessary but is never authorization by itself. The
low-level `udm.py` CLI refuses POST, PUT, and DELETE operations, including non-GET
`raw` calls. The guarded engine has no raw endpoint command.

## Required sequence

Use discover → GET → snapshot → minimal deep-copy edit → exact diff → validate → show
plan → separately approve → apply one write → GET again → compare → verify → report.
Dry-run performs every stage through validation and snapshot but skips authorization
and the final write. A changed current object produces a different token, invalidating
the earlier approval.

Immediately after authorization and immediately before the write, the engine refetches
controller/site identity and the complete safety bundle used by that operation. It
compares the operation-specific precondition material and reruns current conflict and
validation checks. A mutation-relevant authoritative BEFORE change stops as stale and
requires a new plan and approval. Volatile, non-conflicting runtime freshness alone
does not invalidate approval. A fresh conflict always stops before the write. The
engine never regenerates a semantic diff beneath an old approval.

Every normal operation issues at most one authoritative POST, PUT, or DELETE. All
requests after it are GET verification. Mutation transport calls have no automatic
retry. If a response is lost or otherwise ambiguous, the engine refetches state once
to reconcile the outcome. A conclusively applied change is reported as reconciled; an
uncertain result stops without retry and requires human review plus new approval.

## Controller identity, snapshots, and journal

Every plan and restorable snapshot records controller host, site UUID,
`internalReference`, site name, Network version, and timestamp. Restore refuses a
snapshot from any different identity; there is no disaster-recovery override.

Restorable snapshots use schema `unifi-mutation-snapshot-v2`, a SHA-256 content
fingerprint, new immutable files, mode 0600, and a mode-0700 directory. Snapshot
integrity and identity are checked before restore. If a complete object would require
secret redaction, planning stops instead of producing an incomplete rollback object.

Every successful plan and every attempted write has a sanitized JSON record under
`operations/`. Records contain a unique operation ID, timestamps, identity, command,
target, before/after fingerprints, snapshot, approval fingerprint, method/endpoint,
write count, result, verification, rollback snapshot, and rollback-attempt status.
They never contain approval tokens, API keys, passwords, or authentication material.
Both `operations/` and `snapshots/` are ignored by Git.

Port-forward deletion mutates only the authoritative legacy/private port-forward
object. Controller-derived or SYSTEM_DEFINED firewall policies and forwarding status
are refetched and verified; they are never deleted directly. Restore creates the
authoritative port forward from a validated snapshot, then verifies regenerated state
and reports any controller-assigned ID change.

Delete verification requires target-ID absence, absence of a semantic duplicate,
unchanged known unrelated forwards, no unexpected new forward, disappearance of the
associated generated policy and forwarding status, and preservation of unrelated
generated policies. Remaining generated objects produce failed/partial verification;
the engine never tries to remove them. Restore compares semantics without IDs, reports
original and assigned IDs, and verifies regenerated policy/status semantics without
expecting the prior generated-policy ID.

Fixed-IP changes are Level 3. Their approval material is an allowlist: operation,
configured-client ID, MAC, target network ID/name/VLAN, current and requested
`use_fixedip`/`fixed_ip`, semantic diff, controller/site identity, and safety level.
The precondition fingerprint covers the complete nonvolatile configured-client PUT
source plus the authoritative target ID, MAC, network, and current fixed-IP fields.
This prevents a replacement PUT from overwriting an unrelated concurrent edit;
fresh volatile server metadata is rebased into the PUT object. Immediately before PUT,
the engine independently confirms the target still exists and remains on that network, then reruns subnet,
gateway/network/broadcast, other configured-owner/reservation, active-lease, and DHCP
pool checks. A lease for the desired IP is acceptable only when its MAC is the target.
The full configured-client object is preserved and minimally edited. Creation of a
missing configured-client object is unsupported.

UniFi documents Fixed IP Address as a DHCP reservation and supports fixed addresses
outside DHCP scope (with separate local-DNS guidance), so neither inside-pool nor
outside-pool placement is rejected merely by location. The exact pool relationship is
reported. Subnet, network/broadcast/gateway, active-lease, other-reservation, MAC, and
network/VLAN checks remain mandatory. See Ubiquiti's
[DNS Records and Local Hostnames](https://help.ui.com/hc/en-us/articles/15179064940439-UniFi-DNS-Records-and-Local-Hostnames)
and [DHCP Server](https://help.ui.com/hc/en-us/articles/360012097513-UniFi-DHCP-Server)
guidance. A leased IP alone is never client identity.

Firewall policy create/update/delete uses official Integration v1 paths and accepts
only explicit USER_DEFINED, configurable objects. SYSTEM_DEFINED, DERIVED, unknown,
and non-configurable policies are protected. Validation covers zones, network
references, IP/address ranges, action, protocol, connection state, IP version, and
order. Local controller documentation remains authoritative for request schemas.

Firewall snapshots contain the complete target, neighboring policies, full ID/index/
origin ordering, and related source/destination zones. Creation requires an explicit
validated index; the framework never chooses one. Post-write verification removes only
the approved target/result from comparison and requires unrelated ordering to remain
unchanged. SYSTEM_DEFINED, DERIVED, unknown-origin, and non-configurable policy refusal
is enforced inside `mutationlib.py`, even when its functions are called without the CLI.

Rollback never runs automatically. It is a separate mutation with a new current-state
GET, safety snapshot, exact diff, validation, write enablement, and distinct approval
token.

## Output contract

Plan JSON includes the canonical `approval_material` plus a concise `safety_block` with
controller, site, Network version, operation, target, safety level, gate status,
snapshot, current/proposed/precondition/approval fingerprints, secondary effects,
verification plan, rollback path, approval token, and the explicit notice `NO WRITE
HAS OCCURRED.`

Execution JSON includes a `completion_block` with whether mutation was attempted,
authoritative write count, ambiguity status, verification, unrelated-state result,
rollback availability, and operation-record path.
