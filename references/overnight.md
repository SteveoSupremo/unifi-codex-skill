# Scheduled Internet isolation

Run the inventory read plan and safety preflight in SKILL.md, then run
`python3 scripts/mutate.py overnight --plan --mac MAC1 --mac MAC2`.
Additional GETs read the console's OpenAPI document at
`/proxy/network/api-docs/integration.json` and the existing private site-scoped
`stat/sta` active station dataset. The latter is version-sensitive. The installed
schema and official collections identify API capabilities independently of write
enablement. Private client history can contain group IDs without revealing a
group's name, dependencies, or full membership.

## Native implementation plan

1. In Network's Policy Engine, inspect Objects and the Policy Table for
   Family-Overnight-Restricted and Family Overnight Internet Block. Record exact
   IDs, members, references, policy order and enabled state. Stop on duplicate names,
   unexpected members that would newly be blocked, or another policy using the
   group that would gain targets. Obtain separate approval for each change.
2. Review groups on the installed build. Network 10.6.109 exposes firewall policy
   CRUD, a source MAC list and daily time filter. Its official schema has no
   client-device group collection or source device-group selector. Infrastructure
   device tags and traffic-matching lists serve different purposes. Native Object
   Manager is the maintainable alternative. Create the named group with confirmed
   MACs if absent, or add only approved missing MACs. Retain all other membership
   and client settings. Re-read the group and compare the complete membership.
3. Select this group in Objects, Secure > Internet > complete Internet isolation.
   Name the policy Family Overnight Internet Block. Preview coverage from each
   member's actual zone across every Internet exit, including both WANs and any
   policy-routed VPN client. Inspect routing policy assignments and tunnel defaults.
   Avoid blocking the entire VPN zone, which can carry permitted private routes.
   Check rule order against earlier accepts. Preserve the relative order of all
   existing policies. Stop if the UI cannot represent the exact scope.
4. Select every day, local time 20:00 to **next-day** 11:00. Require a preview or
   installed-build documentation establishing rollover, end exclusivity and local
   DST behavior. A stop clock earlier than a start clock is undocumented in the
   10.6.109 OpenAPI. Use two identical-scope intervals only if the controller can
   represent [20:00, next midnight) and [00:00, 11:00) with no gap or overlap.
   A 23:59 stop needs explicit resolution/inclusivity evidence. Withhold apply
   when neither representation is established.
5. The CLI emits hypothetical zone-specific MAC policies for installations where
   the group cannot be selected. Review their narrower selectors, not whole VLANs.
   For either approach use a block, both address families, all ports, protocols
   and connection states. Use counters or policy-filtered logs during validation.
   Prefer counters for ongoing use if drop volume is high. Leave existing DHCP,
   DNS, Wi-Fi, LAN access, management, connection tracking and offload settings alone.
   Let the block expire at 11:00. The normal policy chain resumes.
6. Immediately before any approved change re-read identities, timezone, membership,
   dependencies, complete target and order. Snapshot the original state and review
   the minimal diff. Skip identical objects. Apply one operation, GET/read back
   exact schedule, target, zone, enabled state and ordering. Stop on ambiguity.
   The CLI withholds an apply token for this composite plan. Object Manager changes
   require a human operator and separate approval. Never substitute private writes.

## Verification and maintenance

Record time, client MAC, actual source zone, address family, WAN/tunnel, target
policy ID, counter delta and observed result. Save existing access baselines on
each device and one unrelated control. At 19:59 open a sustained TCP download and
a UDP stream through an authorized external dual-stack host. Keep them running
across 20:00 while creating fresh IPv4 and IPv6 sessions to its literal addresses.
Check both external DNS transports (UDP/TCP 53), HTTPS and an existing and a new
VPN tunnel. Check immediately before/after midnight and 11:00 with fresh sessions.
A successful DNS lookup via local DNS is expected. Test association, DHCP renewal,
local DNS and one previously permitted LAN service throughout. Compare to the
control and record missing baseline connectivity (especially native IPv6).
Repeat across each usable egress without changing production routing for the test.

Established state or accelerated forwarding may let earlier flows continue. Record
bytes delivered across activation, not just socket status, and correlate policy
hits. A missing hit alone cannot distinguish offload, stale routing or idle flows.
Restart persistence requires a second controller read and endpoint tests after
a separately authorized or routine restart. Do not restart for discovery.

For a membership change, confirm the per-SSID MAC on the device, re-check the active
station and history, group references and effective zone, then review the single
member diff. A rotating private address invalidates the match. A stable private
address on the home SSID can preserve the binding. A permitted LAN proxy can originate
external traffic under its own identity. Restricting that proxy changes the scope.

Extra time requires a native, device-scoped pause with a displayed expiry that
resumes only this restriction. Verify expiry in local time and re-read afterward.
No such exception contract was found in the reviewed API. Avoid broad allow rules
or indefinite removal. Roll back in reverse order under fresh approval: compare
current target against the recorded applied version, remove only the created policy
or restore its original fields and position, verify unrelated order, then undo only
the approved membership delta. Delete a newly created group only once unreferenced,
with unchanged membership. Leave pre-existing groups intact. Record each inverse
and its readback. Halt on a changed object. Automated group rollback is unavailable.

[Installed-version public API](https://developer.ui.com/network/v10.6.109/openapi.json) ·
[UniFi Policy Engine](https://help.ui.com/hc/en-us/articles/5546542486551-Traffic-Policy-Management-in-UniFi)

The planner also inspects the private site-scoped v2 collections
`network-members-groups` and `trafficroutes` by GET. Review any returned policy
routes for matching selectors and tunnel exits. An unavailable collection remains
unknown. An empty group collection establishes absence at collection time.
