# Transparent audit benchmarks

Assess WAN exposure, segmentation, IoT isolation, Guest isolation, management-plane security, port-forward hygiene, rule quality, VPN posture, DNS/DHCP posture, wireless security, device/update posture, and configuration hygiene.

Every finding includes severity, category, evidence, why it matters, confidence, recommendation, recommended action class, evidence type (`measured`, `reported`, `inferred`, `correlated`, `not_available`), and automation safety. Scores, when shown, are counts weighted by published severity—not opaque grades. Missing telemetry reduces confidence and never proves safety or rule inactivity.

## Contextual WAN severity

- Critical requires compelling evidence of dangerous exposure and deficient protection; uncertainty alone is not Critical.
- High covers broadly exposed management interfaces, privileged administration, or unknown services on protected infrastructure.
- Medium covers direct public applications, likely reverse-proxy entry points needing validation, and services whose protections cannot be established.
- Low covers intentionally constrained public services with reported source restrictions; restrictions still require verification.
- Informational covers documented, controlled objects or coverage notes without an identified security weakness.

A friendly name never lowers severity by itself. Service ports are hints only. Correlation
uses multiple reported objects, documented roles, and network membership. A TCP 80/443
pair on one destination is consistent with a reverse proxy or HTTPS/ACME gateway, but
does not prove TLS quality, authentication, patching, or downstream policy.

Firewall checks parse available action, source, destination, protocol, port,
direction/zone, enablement, and network identifiers. Duplicate and shadowed rules are
reported only when semantics and ordering provide sufficient evidence; otherwise they
remain candidates for review. Empty or missing rule families produce an explicit
coverage limitation, not a claim that segmentation permits or blocks traffic.

Network 10.5.67 official firewall policies are normalized from `source.zoneId`,
`destination.zoneId`, `action.type`, `action.allowReturnTraffic`, nested
`trafficFilter` blocks (`networkFilter`, `ipAddressFilter`, `portFilter`,
`macAddressFilter`, and `applicationFilter`), `ipProtocolScope`,
`connectionStateFilter`, `index`, `loggingEnabled`, and `metadata.origin`.
Zone `networkIds` correlate to collected network `external_id` values.

Effective segmentation is `ALLOWED` or `BLOCKED` only when ordered, applicable policy
evidence contains a conclusive broad action. Scoped exceptions before a conclusive
default produce `LIMITED`; absent or unresolved evidence produces `UNKNOWN`. A missing
allow never proves a block.
