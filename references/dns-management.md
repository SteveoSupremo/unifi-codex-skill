# Guarded local DNS Host (A) management

## Compatibility and contract evidence

Use official `/proxy/network/integration/v1/sites/{siteId}/dns/policies` with the
discovered site UUID, not the legacy `default` internal name. Version discovery is
GET `/proxy/network/integration/v1/info`; site discovery is GET
`/proxy/network/integration/v1/sites`. All optional reads appear in `inventory.py --plan`.
`mutate.py dns inspect` performs version/site discovery and GET-only DNS collection.

Supported versions are **exactly 10.1.84, 10.5.67, and 10.6.106**. They share the reviewed
A-record DTO and individual resource methods. The public, primary-source OpenAPI
documents are [10.1.84](https://developer.ui.com/network/v10.1.84/openapi.json),
[10.5.67](https://developer.ui.com/network/v10.5.67/openapi.json), and
[10.6.106](https://developer.ui.com/network/v10.6.106/openapi.json).
Reviewed 2026-10-23. No assumption of compatibility with intervening or future builds;
extend the allowlist only after reviewing that build's DNS contracts and tests.

Read-only discovery on 2026-10-23 reported installed Network **10.6.106**, with a valid,
empty official paginated DNS collection. No production writes were attempted. Existing
record shapes and mutation outcomes are tested with synthetic fixtures from the
published contract; this is contract-verified support, not a claim of live write testing.

| Operation | Method | Official path after `/proxy/network/integration` |
| --- | --- | --- |
| List | GET | `/v1/sites/{siteId}/dns/policies?offset=0&limit=200` |
| Full target | GET | `/v1/sites/{siteId}/dns/policies/{dnsPolicyId}` |
| Create | POST | `/v1/sites/{siteId}/dns/policies` |
| Update | PUT | `/v1/sites/{siteId}/dns/policies/{dnsPolicyId}` |
| Delete | DELETE | `/v1/sites/{siteId}/dns/policies/{dnsPolicyId}` |

CREATE/UPDATE uses `IntegrationDnsARecordCreateUpdateDto`: `type: A_RECORD`, boolean
`enabled`, `domain` (1..127 characters), `ipv4Address`, and integer `ttlSeconds`
(0..86400 inclusive). Create defaults to enabled and TTL 300; update preserves
enablement and any unchanged fields. Zero is passed as the documented API value,
without assuming an effective cache duration. GET additionally requires UUID `id`
and `metadata.origin`; writes omit these response-only fields. Only exact
`metadata: {"origin": "USER_DEFINED"}` is writable; system, derived, orchestrated,
non-configurable or unfamiliar metadata is protected.

The private, version-sensitive GET
`/proxy/network/v2/api/site/{internalReference}/static-dns` is prior read evidence
only. Its fields and write behavior are not this implementation's contract. There
is no private write fallback, SSH, direct config editing, or delete/recreate update.

## Scope and validation

Only individual IPv4 Host (A) policies are managed. Requested names are ASCII LDH
host labels, 1..63 characters per label and at most the API's 127-character limit.
Case is normalized to lowercase and one terminal dot is removed. Whitespace, URLs,
empty labels, underscore host labels, IDNs, wildcard names and malformed IPv4/TTL/ID
inputs are refused. The API does not document wildcard semantics in the reviewed
A DTO, so the skill does not guess them. A wildcard TLS certificate does not create
wildcard DNS or authorize it. Observed wildcard/underscore records may be inventoried
as conflict evidence but are not mutated.

The collector validates response/pagination shape and completes at most 10,000
records. Missing pages, changing totals, repeated IDs, unknown record types/origins,
unknown A fields and truncated collections refuse planning. Inventory marks an
unsupported/unavailable DNS dataset unavailable while continuing other collection.
Other known DNS policy types are read for conflicts and preservation, never written.

One identical user-configured record is a NO_OP, even with writes disabled. A different
value/TTL/enablement, duplicate owner or ID, same-name policy of another type, wildcard
covering the name, or ancestor alias/forwarding policy requires review. These checks
include disabled policies. Multiple A answers and even potentially compatible
same-owner non-A records are deliberately refused rather than guessed safe.

## NGINX Proxy Manager use case

Plan **eight separate local A records**, all pointing to **192.168.6.16**, the NGINX
Proxy Manager host:

| Name | IPv4 address |
| --- | --- |
| unifi.mcclurehomelab.duckdns.org | 192.168.6.16 |
| portainer.mcclurehomelab.duckdns.org | 192.168.6.16 |
| webui.mcclurehomelab.duckdns.org | 192.168.6.16 |
| controlbook.mcclurehomelab.duckdns.org | 192.168.6.16 |
| teslamate.mcclurehomelab.duckdns.org | 192.168.6.16 |
| grafana.mcclurehomelab.duckdns.org | 192.168.6.16 |
| cockpit.mcclurehomelab.duckdns.org | 192.168.6.16 |
| nginx.mcclurehomelab.duckdns.org | 192.168.6.16 |

The UniFi proxy already forwards to `https://192.168.1.1:443`, and a trusted wildcard
certificate is already installed. Local DNS sends clients to NGINX Proxy Manager;
its HTTP Host/TLS routing selects the backend. This workflow does not change those
proxy or certificate settings, public Duck DNS records, upstream DNS, DHCP, firewall
rules or port forwarding. Clients must already use a resolver that serves these
gateway-local records; this workflow does not change their resolver configuration.

## Inspect, plan and separately approve one record

Run from the resolved repository (`readlink -f ~/.agents/skills/unifi`):

```bash
cd /home/steve/Projects/unifi-codex-skill
python3 scripts/safety.py status
python3 scripts/mutate.py dns inspect --name unifi.mcclurehomelab.duckdns.org
python3 scripts/mutate.py dns create --name unifi.mcclurehomelab.duckdns.org --ip 192.168.6.16 --ttl 300 --plan
```

Review the complete diff, Level 3 identity/version, API payload, snapshot, verification
and rollback path. Obtain explicit approval for that single record. Only then:

```bash
export UNIFI_ENABLE_WRITES=I_UNDERSTAND_THIS_CHANGES_MY_NETWORK
python3 scripts/mutate.py dns create --name unifi.mcclurehomelab.duckdns.org --ip 192.168.6.16 --ttl 300 --approve TOKEN_FROM_REVIEWED_PLAN
export UNIFI_ENABLE_WRITES=disabled
```

The approval token is exact and identity/state-bound, never a generic `yes`. Any
record change between invocations invalidates it. Plans for the other seven names
must be generated and approved **after** preceding changes complete: a whole-store
precondition intentionally invalidates plans based on an older collection. Do not
batch writes or pre-approve all eight tokens from one starting state.
Explicitly setting `disabled` overrides any write enablement in `.env`; simply
unsetting the shell variable could reveal an enabled `.env` fallback.

Inspect again and, from the affected client/VLAN after caches expire, verify:

```bash
python3 scripts/mutate.py dns inspect --name unifi.mcclurehomelab.duckdns.org
python3 scripts/verify_network.py --host 192.168.1.1 --dns-name unifi.mcclurehomelab.duckdns.org --expected-ip 192.168.6.16
```

Configuration GET verification and resolver verification are distinct. The latter uses
the invoking client's resolver/cache; it does not prove every VLAN, encrypted DNS
client, NGINX backend, certificate or public resolution. If results disagree, investigate
the client resolver path before changing network settings.

## Update, delete and rollback

Find the UUID with `dns inspect`, then plan one minimal operation:

```bash
python3 scripts/mutate.py dns update --id RECORD_UUID --ttl 600 --plan
python3 scripts/mutate.py dns update --id RECORD_UUID --ip 192.168.6.16 --plan
python3 scripts/mutate.py dns delete --id RECORD_UUID --plan
python3 scripts/mutate.py dns restore --snapshot snapshots/TIMESTAMP --plan
# To undo a create, supply the resulting ID reported by successful verification:
python3 scripts/mutate.py dns restore --snapshot snapshots/TIMESTAMP --id CREATED_RECORD_UUID --plan
```

Each apply replaces only `--plan` with `--approve ITS_NEW_TOKEN`, with write enablement
and explicit approval. Restore is an inverse individual operation, not a replay of the
old collection. Identity and snapshot integrity are enforced; modified targets are
refused. Undoing delete may assign a new UUID. All outcomes are journaled locally;
ambiguous outcomes reconcile with up to four GETs, then stop for human review without
retrying the write or automatically rolling back. A concurrent external writer can
still race the last precondition GET because the published API offers no documented
CAS/conditional write. Unknown target fields are refused to avoid lossy PUTs.
