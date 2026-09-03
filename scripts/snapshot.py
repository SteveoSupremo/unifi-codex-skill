#!/usr/bin/env python3
"""Local, Git-ignored snapshots used by guarded mutation planning."""
import argparse, datetime as dt, hashlib, json, os
from pathlib import Path
from unifi_common import ROOT, redact

SNAPSHOT_SCHEMA = "unifi-mutation-snapshot-v2"
IDENTITY_FIELDS = {"controller_host", "site_id", "internal_reference", "site_name", "network_version"}


class SnapshotError(RuntimeError):
    pass


def _write_private(path: Path, payload: object) -> None:
    try:
        with path.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(path, 0o600)
    except FileExistsError as error:
        raise SnapshotError("snapshot files are immutable and cannot be overwritten") from error


def _digest(payload: object) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def create_snapshot(target, object_type, object_id, current, reason, intended=None,
                    base=None, *, restorable=False, metadata=None, controller_identity=None):
    safe_current=redact(current)
    if restorable and safe_current != current:
        raise SnapshotError("target contains sensitive fields that cannot be stored in a restorable snapshot")
    identity = redact(controller_identity or {})
    if restorable and set(identity) != IDENTITY_FIELDS:
        raise SnapshotError("restorable snapshot requires complete controller/site identity")
    stamp=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H%M%S.%fZ")
    folder=(base or ROOT/"snapshots")/stamp
    try:
        folder.mkdir(parents=True, exist_ok=False, mode=0o700)
    except OSError as error:
        raise SnapshotError("unable to create rollback snapshot") from error
    safe_id="".join(c if c.isalnum() or c in "-_" else "_" for c in object_id)
    name=f"{object_type}-{safe_id}.json"
    payload=current if restorable else safe_current
    try:
        _write_private(folder/name, payload)
        manifest={"schema":SNAPSHOT_SCHEMA,"timestamp":stamp,"target":target,
          "object_id":object_id,"object_type":object_type,"reason":reason,
          "restorable":restorable,"intended_change":redact(intended),"files":[name],
          "snapshot_sha256":_digest(payload),"controller_identity":identity,
          "metadata":redact(metadata or {})}
        _write_private(folder/"manifest.json", manifest)
    except OSError as error:
        raise SnapshotError("unable to write rollback snapshot") from error
    return folder


def load_snapshot(path: Path, *, expected_type: str | None = None,
                  expected_identity: dict | None = None) -> tuple[dict, dict]:
    """Load a mutation snapshot from either its folder, manifest, or payload path."""
    try:
        manifest_path = path / "manifest.json" if path.is_dir() else (path if path.name == "manifest.json" else path.parent / "manifest.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("schema") != SNAPSHOT_SCHEMA or not manifest.get("restorable"):
            raise SnapshotError("snapshot is not a restorable guarded-mutation snapshot")
        if expected_type and manifest.get("object_type") != expected_type:
            raise SnapshotError(f"snapshot type must be {expected_type}")
        identity = manifest.get("controller_identity")
        if not isinstance(identity, dict) or set(identity) != IDENTITY_FIELDS:
            raise SnapshotError("snapshot lacks complete controller/site identity")
        if expected_identity is not None and identity != expected_identity:
            raise SnapshotError("snapshot belongs to a different controller or site")
        files = manifest.get("files")
        if not isinstance(files, list) or len(files) != 1:
            raise SnapshotError("snapshot manifest must reference exactly one object")
        relative = Path(files[0])
        if relative.is_absolute() or ".." in relative.parts or len(relative.parts) != 1:
            raise SnapshotError("snapshot manifest contains an unsafe object path")
        payload = json.loads((manifest_path.parent / relative).read_text(encoding="utf-8"))
    except SnapshotError:
        raise
    except (OSError, ValueError, TypeError) as error:
        raise SnapshotError("invalid or unreadable rollback snapshot") from error
    if redact(payload) != payload:
        raise SnapshotError("snapshot contains sensitive fields")
    if manifest.get("snapshot_sha256") != _digest(payload):
        raise SnapshotError("snapshot integrity check failed")
    return manifest, payload

def main():
    p=argparse.ArgumentParser(); p.add_argument("--target",required=True); p.add_argument("--type",required=True)
    p.add_argument("--id",required=True); p.add_argument("--input",required=True,type=Path); p.add_argument("--reason",required=True); a=p.parse_args()
    print(create_snapshot(a.target,a.type,a.id,json.loads(a.input.read_text()),a.reason))
if __name__=="__main__": main()
