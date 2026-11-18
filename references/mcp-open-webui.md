# Read-only MCP for Open WebUI

This optional server exposes native **Streamable HTTP** at `/mcp`. The existing CLI
still uses only the Python standard library; MCP dependencies are isolated in `.venv`
and pinned in `requirements-mcp.txt`. Python 3.10+ is required by the SDK; the Docker
image and homeserver tests use Python 3.14. The server uses the official MCP Python
SDK 1.x maintenance line, explicitly pinned to avoid an unreviewed major migration.

## Safety and configuration

- Reuses `unifi_common.load_env`, `UDMClient.get_optional`, and inventory site selection.
  Environment variables override the existing project `.env` as in the CLI.
- Every controller request is GET, restricted to the configured controller. Redirects
  are refused, proxy environment variables are ignored, and reads have a 15-second
  socket timeout. There is no raw endpoint tool, mutation tool, automatic action,
  approval operation, or rollback operation in MCP. CLI mutation safeguards are unchanged.
- Native startup refuses an enabled write gate. Compose forces it disabled inside the
  container without changing CLI configuration. Calls have bounded pagination and four
  concurrent workers. No controller request occurs during startup or tool discovery.
- A separate `UNIFI_MCP_TOKEN` bearer token is required on **every** HTTP request.
  Generate a random 256-bit value using `python3 scripts/mcp_token.py`; this writes it
  directly into the existing ignored `.env` with mode 0600 and never displays it.
  Existing nonempty tokens are preserved. Do not reuse the controller API key.
- Responses project useful fields, recursively redact sensitive fields and configured
  secret values, and suppress controller error bodies. SDK payload logging and HTTP
  access logging are disabled. Treat remaining names, MACs, addresses and policies as
  private network information; grant Open WebUI access only to appropriate users.
- MCP honors `UNIFI_VERIFY_TLS` (default true); an explicit false retains support for
  your existing self-signed-controller configuration. This does not change the preserved
  low-level CLI's TLS behavior. Use a trusted controller certificate when available.
- HTTP Host allowlisting and Origin checks remain enabled. Browser-origin requests are
  refused; Open WebUI connects from its backend. `UNIFI_MCP_ALLOWED_HOSTS` can add exact
  `host:port` entries if needed; it does not allow wildcard entries.

## Tools and result coverage

| Tool | Information | Source |
|---|---|---|
| `controller_info` | Installed Network application version | Official Integration v1 |
| `discover_sites` | Site IDs, internal references and names | Official Integration v1 |
| `networks` | Networks, VLANs, subnets, DHCP ranges | Legacy/private GET |
| `active_clients` | Connected clients, names, MACs, IPs | Official Integration v1 |
| `client_lookup` | Partial case-insensitive name or exact MAC/IP | Local filtering of active-client page |
| `firewall_policies` | Zone policy configuration | Official Integration v1 |
| `port_forwards` | Configured forwarding rules | Legacy/private GET |
| `ids_ips_events` | Legacy threat events where available | Version-sensitive legacy GET |
| `network_summary` | Application info and per-dataset counts/coverage | Bounded reads of above datasets |

Tools accept optional `site` (UUID, internal reference, or name), `limit` (1–500),
`offset` (0–100000). `client_lookup` additionally requires `query`. Information tools
have the same common arguments for consistency; summary uses a fixed maximum of 500
records per dataset. For paginated results, continue from `offset + returned`; client
lookup must continue from `offset + scanned` because filtering changes the result count.
A lookup only searches active clients in that page, not offline/historical clients.
`total` on lookup is the source collection count, not a count of all matches.

Results report `live_mutation: false`, `status`, API family, and collection bounds.
Summary coverage distinguishes unavailable datasets from empty ones. No live API
compatibility was tested during development: all tests use synthetic controller data.

IDS/IPS GET support is version-sensitive and may be unavailable or misleadingly empty
on recent firmware. The tool labels any successful legacy response `partial`, caps it
at 500 events in the controller-defined window, and does not infer safety from empty
results. It never falls back to the CLI's POST-based system-log API. Unsupported or
malformed responses produce `unavailable`, without exposing raw errors. A firmware
requiring POST for event queries needs a separately reviewed extension, not a relaxed
transport guard. Network summary counts do not prove WAN reachability, effective
firewall behavior or absence of threats. HP ProCurve remains outside UniFi control.

## Local installation and tests

```bash
cd ~/Projects/unifi-codex-skill
python3 -m venv .venv
.venv/bin/pip install -r requirements-mcp.txt
python3 scripts/mcp_token.py
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/mcp_server.py
```

Native startup binds `127.0.0.1:8765` by default. A private RFC1918 IP can be selected
with `UNIFI_MCP_BIND`; public and wildcard bindings are refused. On a LAN binding,
add the exact `IP:8765` to `UNIFI_MCP_ALLOWED_HOSTS` and use trusted TLS termination
before sending bearer tokens across an untrusted network. Never create a router port
forward or public reverse-proxy route. The recommended Docker deployment needs neither.

Without MCP dependencies, the original standard-library suite still runs and the HTTP
MCP tests are explicitly skipped. Use the `.venv` command above for the full suite.

## Docker Compose on this homeserver

Open WebUI already uses Docker network `open-webui_default`. The provided Compose
service joins that existing network and publishes **no host ports**. It binds only its
private container IP, runs as UID/GID 1000 with dropped capabilities and a read-only
filesystem, and mounts the existing `.env` read-only. The Docker build context excludes
`.env`, `.git`, virtual environments, inventories, reports and snapshots. If the file
owner differs, set `UNIFI_MCP_UID`/`UNIFI_MCP_GID` accordingly. The external network must
exist; override `UNIFI_MCP_DOCKER_NETWORK` for another installation.

```bash
cd ~/Projects/unifi-codex-skill
python3 scripts/mcp_token.py
docker compose config --quiet
docker compose build
docker compose up -d
```

Do not run `docker compose config` without `--quiet` against configurations that may
include credentials. The supplied configuration mounts the file rather than injecting
its secrets through Compose interpolation or image build arguments.

To stop: `docker compose down`. To update code/dependencies: rebuild and recreate the
service. After editing `.env`, restart the service to reload it. To rotate the MCP token,
edit its value privately in `.env`, restart, then update the saved Open WebUI bearer key.
Neither startup nor restart changes controller configuration.

## Proposed Open WebUI connection

In **Admin Settings → Integrations → External Tool Servers → Add Connection**
(older versions may label the page External Tools), use:

| Setting | Value |
|---|---|
| Name | UniFi read-only |
| Type | MCP (Streamable HTTP) |
| Server URL | `http://unifi-mcp:8765/mcp` |
| Authentication | Bearer |
| Key | Value of `UNIFI_MCP_TOKEN` from local `.env` |
| Access | Only users/groups authorized to inspect this network |

Copy the MCP token privately in your editor; do not paste the `.env` or UniFi API key
into a chat. The HTTP header is `Authorization: Bearer <UNIFI_MCP_TOKEN>`; when Open
WebUI provides a separate Bearer Key field, enter only the token there. The URL is for
Open WebUI's backend on the shared Docker network, not a browser on another computer.
If both processes run directly on the host instead, use `http://127.0.0.1:8765/mcp`.
Do not select OpenAPI or legacy SSE. No MCPO proxy is required.

Sources: [Open WebUI native MCP configuration](https://docs.openwebui.com/features/extensibility/mcp/)
and [official Python SDK Streamable HTTP](https://github.com/modelcontextprotocol/python-sdk/tree/v1.x).
