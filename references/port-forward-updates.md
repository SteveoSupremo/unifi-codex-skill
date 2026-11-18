# Port-forward destination updates

`scripts/mutate.py port-forward update` changes only `fwd` on one existing legacy
port-forward object. It supports the locally observed Network **10.6.106** schema
only, using private `/proxy/network/api/s/{internalReference}/rest/portforward/{id}`
GET/PUT. This endpoint is version-sensitive and is not the official Integration API.
Unknown fields, versions, malformed IDs, or collection/detail disagreement stop planning.

The target must remain in the same unambiguous configured IPv4 LAN subnet. Gateway,
network, broadcast, loopback, multicast and link-local targets are refused. Destination
changes to another VLAN, protocol/port changes, and rule creation are out of scope.

The full authoritative object is deep-copied; only `fwd` changes. Public ports, protocol,
WAN selections, source restrictions, enablement and every other field are preserved.
The Level 3 snapshot, exact approval token, write-enablement phrase, controller identity
and immediate pre-write state checks are mandatory. The operation issues one PUT and
never retries it. Lost responses are reconciled through bounded GET-only verification.
Unrelated forwarding objects and firewall policies must remain unchanged, and related
generated firewall/status destinations must reflect the new IP. Generated policies are
never directly edited. Configuration verification does not prove external reachability.

Moving HTTP/HTTPS forwarding to a reverse proxy makes its configured proxy hosts
internet-accessible, subject to the existing WAN/source restrictions. Include the
actual proxy hosts in the user-facing change description.

```bash
python3 scripts/mutate.py port-forward update --id LEGACY_24_HEX_ID \
  --expect fwd=192.168.6.25 --forward-ip 192.168.6.16 --plan
# After authorization, use the exact emitted token, with write enablement:
UNIFI_ENABLE_WRITES=I_UNDERSTAND_THIS_CHANGES_MY_NETWORK \
  python3 scripts/mutate.py port-forward update --id LEGACY_24_HEX_ID \
  --expect fwd=192.168.6.25 --forward-ip 192.168.6.16 --approve TOKEN
```

Each forward needs a fresh plan against the current collection. To undo an update,
use `port-forward revert --snapshot SNAPSHOT_DIR --plan`, then separately approve
that inverse operation. The source snapshot's integrity and controller identity are
checked; a changed applied target is refused. This preserves the existing object ID
and uses PUT, not deletion/recreation. `port-forward restore` remains the separate
workflow for restoring a deleted forward.
