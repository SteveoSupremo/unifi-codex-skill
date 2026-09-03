• ## UniFi Codex skill capability report

  Project: Projects/unifi-codex-skill
  Git status: clean and synchronized with origin/master
  Current safety state: credentials configured, READ_ONLY, live mutation disabled

  ### Important installation issue

  Moving the repository broke the installed skill symlink:

  ~/.agents/skills/unifi -> /home/steve/unifi-codex-skill

  That old target no longer exists. Until fixed, $unifi may not activate automatically in a new Codex
  conversation.

  The appropriate repair is:

  ln -sfn /home/steve/Projects/unifi-codex-skill ~/.agents/skills/unifi

  I have not changed it because this request was for a report.

  ## What the skill is designed to do

  The skill provides a read-only-first workflow for:

  - Discovering the UniFi Network application version and site.
  - Collecting a sanitized network inventory.
  - Auditing firewall policy and VLAN segmentation.
  - Reviewing WAN port forwards and Internet-exposure candidates.
  - Correlating forwarded addresses with clients, devices, networks, and firewall policies.
  - Reporting VPN, IDS/IPS, and UPnP configuration posture.
  - Detecting limited desired-state network drift.
  - Producing human-readable Markdown reports.
  - Producing machine-readable JSON for ChatGPT or other tools.
  - Taking redacted configuration snapshots.
  - Preparing rollback diffs.
  - Running basic post-change network verification.
  - Planning guarded configuration changes.

  It operates against a local UniFi controller using an API key stored in .env. Secrets, raw inventories, reports,
  and snapshots are excluded from Git.

  ## Information it can collect

  The inventory collector previews every request before contacting the controller.

  ### Official UniFi Integration API

  It attempts to collect:

   Dataset                    What it provides
  ━━━━━━━━━━━━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Application information    Installed UniFi Network version
  ─────────────────────────  ───────────────────────────────────────────
   Sites                      Correct site ID and internal reference
  ─────────────────────────  ───────────────────────────────────────────
   Connected clients          Names, IPs, MACs, and network association
  ─────────────────────────  ───────────────────────────────────────────
   Firewall zones             Zone names and associated networks
  ─────────────────────────  ───────────────────────────────────────────
   Firewall policies          Ordered zone-based security policy
  ─────────────────────────  ───────────────────────────────────────────
   Wi-Fi broadcasts           SSIDs and available security information
  ─────────────────────────  ───────────────────────────────────────────
   WAN interfaces             WAN definitions and interface context
  ─────────────────────────  ───────────────────────────────────────────
   VPN servers                Remote-access VPN configuration
  ─────────────────────────  ───────────────────────────────────────────
   Site-to-site VPN           Configured tunnel information

  Official paginated collections are retrieved with repeated GET requests until all pages are collected.

  ### Legacy or private read-only endpoints

  Where the official API lacks equivalent data, it also attempts to collect:

   Dataset                   Purpose
  ━━━━━━━━━━━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Health                    Site health information
  ────────────────────────  ──────────────────────────────────────────────────────
   System information        Controller and application details
  ────────────────────────  ──────────────────────────────────────────────────────
   Networks                  VLANs, subnets, isolation, and network configuration
  ────────────────────────  ──────────────────────────────────────────────────────
   Devices                   UniFi gateways, switches, and access points
  ────────────────────────  ──────────────────────────────────────────────────────
   Legacy firewall rules     Older firewall configuration
  ────────────────────────  ──────────────────────────────────────────────────────
   Traffic rules             Private v2 traffic-rule objects
  ────────────────────────  ──────────────────────────────────────────────────────
   Port forwards             Configured NAT/forwarding rules
  ────────────────────────  ──────────────────────────────────────────────────────
   UPnP forwarding status    Possible runtime or dynamic forwarding entries
  ────────────────────────  ──────────────────────────────────────────────────────
   IDS/IPS settings          Configured threat-management posture

  These endpoints are version-sensitive. Unsupported optional endpoints are recorded as unavailable instead of
  stopping the entire inventory.

  ## What the audit currently analyzes

  ### WAN exposure and port forwards

  For each enabled port forward, the skill tries to determine:

  - WAN port and protocol.
  - Internal destination address and port.
  - Destination device or client.
  - Destination VLAN/network.
  - Whether the destination is protected.
  - Source-address restriction.
  - Likely service based on port and naming evidence.
  - Whether it is an administrative interface, application service, VPN, reverse proxy, or unknown service.
  - Whether an official firewall policy can be correlated with the forward.
  - Severity, confidence, evidence type, and recommended action.

  Recognized service hints currently include:

  - 8006: possible Proxmox management
  - 8123: possible Home Assistant
  - 5678: possible n8n
  - 80 and 443: web/reverse-proxy pattern
  - 22: possible SSH
  - 3389: possible RDP
  - 5900: possible VNC

  If ports 80 and 443 terminate on the same host, the auditor recognizes that as a likely reverse-proxy or HTTPS/
  ACME pattern.

  Recommendations use classifications such as:

  - KEEP / VERIFY
  - VERIFY
  - REVIEW
  - HARDEN
  - CANDIDATE FOR REMOVAL
  - UNKNOWN — INVESTIGATE

  These are recommendations, not authorization to modify anything.

  ### Firewall policy

  The skill normalizes official firewall policies into a consistent representation containing:

  - Policy name and ID.
  - Enabled state.
  - Ordered index.
  - Source and destination zones.
  - Source and destination filters.
  - Network, address, port, MAC, and application scopes.
  - Protocol and IP version.
  - Connection-state filters.
  - Logging state.
  - System-defined versus user-defined origin.
  - Return-traffic setting.

  It can identify review candidates such as:

  - Broad low-trust-to-trusted allows.
  - Guest or IoT access into trusted zones.
  - Broad access into server networks.
  - Broad server egress.
  - Untrusted access to gateway management.
  - Duplicate policy candidates.
  - Disabled policy candidates.

  ### Effective segmentation

  For selected relationships, it attempts to classify effective policy as:

  - ALLOWED
  - BLOCKED
  - LIMITED
  - UNKNOWN

  Relationships currently include paths among:

  - Default
  - Family
  - IoT
  - Servers
  - Media
  - Guest
  - Gateway/management

  The analysis is deliberately conservative. A missing allow rule does not automatically prove that traffic is
  blocked.

  ### VPN and management posture

  The report shows:

  - Collected VPN servers.
  - Server type and enabled state.
  - Site-to-site tunnel count.
  - Whether a plausible remote-access path exists.

  It does not test actual reachability, authentication strength, or authorization after connecting.

  ### IDS/IPS posture

  It reports available settings such as:

  - IDS/IPS mode.
  - Whether threat management appears enabled.
  - Advanced filtering preference.
  - Memory-optimized setting.
  - Honeypot setting.
  - Number of enabled categories, when available.

  This reports configuration, not demonstrated detection effectiveness.

  ### UPnP and dynamic exposure

  The skill compares forwarding-status entries with configured port forwards and reports entries that do not
  appear to match normal configured forwards.

  An unmatched entry is only a dynamic-exposure candidate; it is not proof that UPnP created it.

  ### Network desired-state drift

  The current desired-state check expects these VLANs:

   VLAN    Name       Expected subnet
  ━━━━━━  ━━━━━━━━━  ━━━━━━━━━━━━━━━━━
      1    Default    192.168.1.0/24
  ──────  ─────────  ─────────────────
      2    Family     192.168.2.0/24
  ──────  ─────────  ─────────────────
      3    IoT        192.168.3.0/24
  ──────  ─────────  ─────────────────
      4    Servers    192.168.6.0/24
  ──────  ─────────  ─────────────────
      5    Media      192.168.7.0/24
  ──────  ─────────  ─────────────────
     99    Guest      192.168.99.0/24

  At present, it primarily reports expected VLANs that were not observed. It does not yet provide comprehensive
  field-by-field desired-state reconciliation.

  ## Standard read-only workflow

  From the repository:

  cd ~/Projects/unifi-codex-skill

  Check safety and credentials without printing secrets:

  python3 scripts/safety.py status
  git check-ignore .env

  Run mocked tests:

  python3 -m unittest discover -s tests -v

  Preview every planned controller request:

  python3 scripts/inventory.py --plan

  Refresh the sanitized inventory:

  python3 scripts/inventory.py --output inventory.json

  Run the complete audit:

  python3 scripts/audit.py all --input inventory.json --report

  The Markdown report will be written under reports/, which is ignored by Git.

  ## Focused audit commands

  Firewall and segmentation:

  python3 scripts/audit.py firewall --input inventory.json

  WAN exposure and port forwards:

  python3 scripts/audit.py exposure --input inventory.json

  Network desired-state drift:

  python3 scripts/audit.py network --input inventory.json

  Health, performance, or Wi-Fi coverage:

  python3 scripts/audit.py health --input inventory.json
  python3 scripts/audit.py performance --input inventory.json
  python3 scripts/audit.py wifi --input inventory.json

  The health, performance, and Wi-Fi analyzers are currently shallow. They mainly report collection coverage or
  missing telemetry rather than providing deep optimization recommendations.

  ## Using the output with ChatGPT

  Generate machine-readable JSON:

  python3 scripts/audit.py all \
    --input inventory.json \
    --json-output all-audit.json

  You can then attach all-audit.json to a ChatGPT conversation and ask:

  > Review this sanitized UniFi audit. Prioritize high-confidence risks, separate verified facts from inferences,
  > explain all important unknowns, and propose a read-only investigation plan. Do not recommend automatic removal
  > or make configuration changes.

  For firewall review:

  > Analyze the effective segmentation matrix and firewall policy findings. Explain which relationships are
  > ALLOWED, BLOCKED, LIMITED, or UNKNOWN and cite the policy evidence. Identify where missing or ambiguous
  > evidence prevents a conclusion.

  For port forwards:

  > Review every port-forward assessment. Group them into administrative interfaces, application services,
  > reverse-proxy entry points, VPN listeners, and unknown services. Explain which should be kept, verified,
  > hardened, or investigated.

  For desired-state planning:

  > Compare this audit to my intended network policy. Ask me to define any unresolved inter-VLAN access
  > requirements before proposing firewall changes.

  ChatGPT outside the Codex environment cannot directly run these local scripts or contact your controller. It can
  analyze an attached sanitized report. Codex with the installed $unifi skill can execute the guarded local
  workflow.

  ## Useful natural-language requests for Codex

  Once the skill symlink is repaired, examples include:

  > $unifi Refresh my sanitized inventory and give me a read-only complete security audit. Do not make any
  > changes.

  > $unifi Show every enabled WAN port forward, its destination device and VLAN, related firewall-policy evidence,
  > source restrictions, confidence, and important unknowns.

  > $unifi Audit Guest and IoT access to Default, Family, Servers, Media, and gateway management. Treat incomplete
  > evidence as UNKNOWN.

  > $unifi Check whether IDS/IPS, VPN, and UPnP information is available and summarize the configured posture
  > without testing reachability.

  > $unifi Compare the current networks against references/desired-state.yaml and report drift. Do not modify the
  > controller.

  > $unifi Diagnose why a client cannot reach a service. Collect current state read-only, identify the client
  > network and relevant policies, and show the evidence.

  > $unifi Prepare a proposed firewall change, snapshot plan, complete before/after diff, risk analysis, rollback
  > plan, and verification procedure. Do not apply it.

  ## Updating information versus changing configuration

  There are two different meanings of “update.”

  ### Refreshing information

  This is supported and read-only:

  1. Run inventory collection again.
  2. Save a new sanitized inventory.json.
  3. Run the desired audits locally.
  4. Compare the new results with previous sanitized results.
  5. Produce a refreshed report.

  A good request is:

  > $unifi Refresh the inventory and compare it with my last sanitized inventory. Report added or removed clients,
  > devices, networks, forwards, and firewall policies. Do not change the controller.

  The repository does not yet have a dedicated historical drift database, so comparison may require keeping two
  ignored sanitized inventories and comparing them locally.

  ### Updating the UniFi controller

  Live configuration changes are not fully implemented in the safe high-level tooling.

  The intended process is:

  discover → GET full object → snapshot → deep-copy
  → minimal proposed edit → full diff → validate
  → explicit user approval → apply one change
  → GET again → compare → verify → report

  Safety levels are:

   Level    Meaning
  ━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   0        Read-only discovery and analysis
  ───────  ───────────────────────────────────────────────────────────────────────────────────────────────────────
   1        Exact operational action requested by the user
  ───────  ───────────────────────────────────────────────────────────────────────────────────────────────────────
   2        Configuration change requiring snapshot, diff, approval, and verification
  ───────  ───────────────────────────────────────────────────────────────────────────────────────────────────────
   3        Critical infrastructure: WAN, gateway management, DNS, DHCP, routing, trunks, protected servers, VPN
            administration

  Live mutation also requires:

  UNIFI_ENABLE_WRITES=I_UNDERSTAND_THIS_CHANGES_MY_NETWORK

  However, setting that variable alone is not authorization. The exact change must still be requested and
  approved.

  At present:

  - Snapshot creation works.
  - Rollback diff planning works.
  - Basic TCP/DNS verification works.
  - The rollback tool is plan-only.
  - Safe high-level live application is not finished.
  - The preserved low-level udm.py has mutation capabilities, but the skill explicitly prohibits using its
    unrestricted raw mutation path for normal changes.

  Therefore, use the skill today for collection, analysis, troubleshooting, and carefully prepared change plans—
  not unattended controller modifications.

  ## Known unfinished areas

  The tracked Projects/unifi-codex-skill/TODO.md records these limitations:

  - matchOpposite firewall-filter semantics are retained but not yet applied.
  - Missing or malformed policy indexes need safer handling.
  - allowReturnTraffic semantics need further validation.
  - Combined filters and unusual policy actions need more schema testing.
  - Unresolved network and zone IDs need better reporting.
  - Empty versus unavailable policy collections need clearer distinction.
  - VPN, IDS/IPS, and UPnP edge cases need more focused tests.
  - UPnP reconciliation may need better equivalence matching.
  - More controller-version-specific sanitized captures should be tested.

  Until these are resolved, firewall conclusions should be treated as useful but conservative—not comprehensive
  proof of actual packet behavior.

  ## Things the skill cannot prove

  It does not currently:

  - Externally scan your public IP.
  - Prove a configured port forward is reachable from the Internet.
  - Test application authentication.
  - Inspect TLS quality.
  - Inspect downstream reverse-proxy routes.
  - Fully prove stateful firewall behavior.
  - Control or fully inventory the HP ProCurve switch.
  - Automatically remove “unused” rules.
  - Safely perform general live configuration changes.
  - Replace a human decision for protected infrastructure.

  Two maintenance notes also need attention:

  - The installed $unifi symlink is broken after the repository move.
  - The README still describes origin as HTTPS, but the actual remote now correctly uses SSH.

