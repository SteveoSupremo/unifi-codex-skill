# Security policy

- Default-deny between trust zones where practical.
- Do not grant IoT broad access to trusted networks.
- Isolate Guest from private RFC1918 space except documented services.
- Restrict management interfaces to trusted administrative sources.
- Deny WAN inbound except explicitly required services; prefer VPN for administration.
- Require a documented purpose for every port forward.
- Avoid Any/Any rules unless demonstrably necessary.
- Never weaken meaningful controls merely to improve performance or a benchmark score; explain tradeoffs.

These are audit principles, not authorization or complete firewall intent.
