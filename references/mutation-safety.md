# Mutation safety

Level 0 reads are allowed after credential safeguards. Level 1 operational actions require an exact request. Level 2 configuration requires current-state GET, snapshot, full proposed diff, validation, explicit approval, one change, refetch, verification, and report. Level 3 covers WAN, gateway/management, DHCP/DNS, routing, native VLAN/trunk, server and VPN administration; refuse casual or ambiguous requests.

Live mutation additionally requires `UNIFI_ENABLE_WRITES=I_UNDERSTAND_THIS_CHANGES_MY_NETWORK`. Dry-run does not waive discovery or diff requirements. Rollback is itself a mutation and follows the same approval process.
