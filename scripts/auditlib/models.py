from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class PortForwardAssessment:
    name: str
    protocol: str
    wan_port: str
    internal_ip: str
    internal_port: str
    destination_name: str = "unknown"
    destination_role: str = "unknown"
    network: str = "unknown"
    source_restriction: str = "unknown"
    likely_service: str = "unknown"
    exposure_class: str = "Unknown"
    severity: str = "medium"
    evidence: list[str] = field(default_factory=list)
    confidence: str = "low"
    action_class: str = "UNKNOWN — INVESTIGATE"
    protected_resource: bool = False
    firewall_correlation: str = "unknown"
    enabled: bool = True

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
