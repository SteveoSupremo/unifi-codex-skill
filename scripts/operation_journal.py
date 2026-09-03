#!/usr/bin/env python3
"""Sanitized, Git-ignored operation journal for mutation plans and attempts."""
from __future__ import annotations

import datetime as dt
import json
import os
import uuid
from pathlib import Path
from typing import Any

from unifi_common import ROOT, redact


JOURNAL_SCHEMA = "unifi-operation-record-v1"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def new_operation_id() -> str:
    return str(uuid.uuid4())


class OperationJournal:
    def __init__(self, base: Path | None = None):
        self.base = base or ROOT / "operations"

    @staticmethod
    def _safe(record: dict[str, Any]) -> dict[str, Any]:
        safe = redact(record)
        if "approval_token" in safe:
            raise ValueError("approval tokens must never be written to the operation journal")
        return safe

    def create(self, record: dict[str, Any]) -> Path:
        self.base.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.base, 0o700)
        operation_id = str(record["operation_id"])
        path = self.base / f"{operation_id}.json"
        payload = {"schema": JOURNAL_SCHEMA, **self._safe(record)}
        try:
            with path.open("x", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.chmod(path, 0o600)
        except FileExistsError as error:
            raise RuntimeError("operation record already exists") from error
        return path

    def update(self, path: Path, changes: dict[str, Any]) -> None:
        try:
            current = json.loads(path.read_text(encoding="utf-8"))
            current.update(self._safe(changes))
            temporary = path.with_suffix(".tmp")
            with temporary.open("x", encoding="utf-8") as handle:
                json.dump(current, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.chmod(temporary, 0o600)
            temporary.replace(path)
            os.chmod(path, 0o600)
        except (OSError, ValueError, TypeError) as error:
            raise RuntimeError("unable to update operation record") from error
