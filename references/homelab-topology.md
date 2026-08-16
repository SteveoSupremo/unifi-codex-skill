# HomeLab topology

Internet → UDM Pro (gateway/firewall/routing) → VLAN trunk → HP ProCurve 2810-24G (Layer-2 switching).

| VLAN | Name | Subnet | Intent |
|---:|---|---|---|
| 1 | Default | 192.168.1.0/24 | management/default; protected |
| 2 | Family | 192.168.2.0/24 | trusted family clients |
| 3 | IoT | 192.168.3.0/24 | untrusted devices |
| 4 | Servers | 192.168.6.0/24 | protected servers |
| 5 | Media | 192.168.7.0/24 | media devices |
| 99 | Guest | 192.168.99.0/24 | isolated guests |

The ProCurve and its physical ports are outside the UniFi API. Never translate a ProCurve-port request into a UniFi switch mutation. Classify UniFi physical ports as active, inactive, candidate for review, intentionally reserved, or unknown; disconnection alone never authorizes disabling.
