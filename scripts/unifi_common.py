#!/usr/bin/env python3
"""Shared, read-only-first utilities. Standard library only."""
from __future__ import annotations
import copy, difflib, json, os, re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
WRITE_PHRASE = "I_UNDERSTAND_THIS_CHANGES_MY_NETWORK"
SECRET_KEYS = re.compile(r"(api.?key|password|passwd|secret|token|authorization|cookie)", re.I)

def load_env(path: Path | None = None) -> dict[str, str]:
    values = dict(os.environ)
    target = path or ROOT / ".env"
    if target.is_file():
        for raw in target.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            key, value = line.split("=", 1)
            values.setdefault(key.strip(), value.strip().strip("'\""))
    return values

def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: "<redacted>" if SECRET_KEYS.search(str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, list): return [redact(v) for v in value]
    if isinstance(value, tuple): return tuple(redact(v) for v in value)
    if isinstance(value, str):
        return re.sub(r"(?i)(x-api-key|authorization)(\s*[:=]\s*)\S+", r"\1\2<redacted>", value)
    return value

def writes_enabled(env: dict[str, str] | None = None) -> bool:
    return (env or load_env()).get("UNIFI_ENABLE_WRITES") == WRITE_PHRASE

def require_write_authorization(*, explicit: bool, approved: bool, level: int, dry_run: bool) -> None:
    if level not in (1, 2, 3): raise ValueError("permission level must be 1-3")
    if not explicit: raise PermissionError("an exact user request is required")
    if level >= 2 and not approved: raise PermissionError("explicit approval of the shown diff is required")
    if not dry_run and not writes_enabled(): raise PermissionError("live writes are disabled")

def deep_modified(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(current)
    for key, value in changes.items(): result[key] = copy.deepcopy(value)
    return result

def json_diff(before: Any, after: Any) -> str:
    a = json.dumps(redact(before), indent=2, sort_keys=True).splitlines()
    b = json.dumps(redact(after), indent=2, sort_keys=True).splitlines()
    return "\n".join(difflib.unified_diff(a, b, fromfile="current", tofile="proposed", lineterm=""))

@dataclass(frozen=True)
class Finding:
    severity: str; category: str; title: str; evidence: str; why: str
    confidence: str = "medium"; recommendation: str = "Review with a human."
    evidence_type: str = "reported"; safe_to_automate: bool = False
    action_class: str = "REVIEW"
    details: dict[str, Any] | None = None
    def as_dict(self) -> dict[str, Any]: return self.__dict__.copy()
