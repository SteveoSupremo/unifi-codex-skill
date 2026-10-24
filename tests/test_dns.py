"""All DNS controller transport is synthetic; no production mutation tests."""
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import socket
from unittest import mock
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))

import mutate
from dns_api import (DnsContractError, SUPPORTED_VERSIONS, fetch_records, require_version,
                     validate_a, validate_collection)
from inventory import collect_inventory, build_plan
from mutationlib import (AmbiguousWriteError, ControllerIdentity, ControllerWriteError,
                         GuardedMutator, MutationError, StateMismatch, StaleApprovalError, ValidationError)
from snapshot import SnapshotError, load_snapshot
from test_inventory import FakeClient, site
from unifi_common import WRITE_PHRASE
from verify_network import verify


TARGET = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
NEW = "33333333-3333-4333-8333-333333333333"
NAME = "unifi.mcclurehomelab.duckdns.org"
ADDRESS = "192.168.6.16"
IDENTITY = ControllerIdentity("udm.test", "site", "default", "Test Site", "10.6.106")


def a_record(identifier=TARGET, name=NAME, address=ADDRESS, **extra):
    return {"id": identifier, "type": "A_RECORD", "enabled": True, "domain": name,
            "ipv4Address": address, "ttlSeconds": 300, "metadata": {"origin": "USER_DEFINED"}, **extra}


def page(data, offset=0, total=None):
    return {"offset": offset, "limit": 200, "count": len(data),
            "totalCount": len(data) if total is None else total, "data": copy.deepcopy(data)}


class DnsClient:
    base = ""

    def __init__(self, records=None, mode="normal", fresh_change=None):
        self.records = copy.deepcopy(records if records is not None else [a_record(OTHER, "other.example.test")])
        self.mode, self.fresh_change = mode, fresh_change
        self.calls = []
        self.collection_reads = 0
        self.pending = None
        self.after_reads = 0

    def get_optional(self, endpoint, *, unwrap=True):
        return self.get(endpoint)

    def get(self, endpoint):
        self.calls.append(("GET", endpoint))
        path = endpoint.split("?", 1)[0]
        if path.endswith("/integration/v1/info"):
            return {"applicationVersion": IDENTITY.network_version}
        if path.endswith("/integration/v1/sites"):
            return [site("site", "default", "Test Site")]
        if path.endswith("/dns/policies"):
            self.collection_reads += 1
            if self.collection_reads == 3 and self.fresh_change:
                self.fresh_change(self)
            if self.pending:
                self.after_reads += 1
                if self.after_reads >= 2:
                    self.records.append(self.pending)
                    self.pending = None
            offset = int(parse_qs(urlsplit(endpoint).query).get("offset", [0])[0])
            return page(self.records[offset:offset + 200], offset, len(self.records))
        if "/dns/policies/" in path:
            target = path.rsplit("/", 1)[1]
            return copy.deepcopy(next(r for r in self.records if r["id"] == target))
        raise AssertionError("Unexpected synthetic endpoint")

    def guarded_write(self, method, endpoint, body):
        self.calls.append((method, endpoint, copy.deepcopy(body)))
        if self.mode == "rejected":
            raise ControllerWriteError(status=400, error_kind="http")
        if self.mode != "timeout-none":
            if method == "POST":
                created = {**copy.deepcopy(body), "id": NEW, "metadata": {"origin": "USER_DEFINED"}}
                if self.mode == "delayed":
                    self.pending = created
                else:
                    self.records.append(created)
                if self.mode == "duplicate":
                    self.records.append({**created, "id": TARGET})
            elif method == "PUT":
                identifier = endpoint.rsplit("/", 1)[1]
                self.records = [{**r, **copy.deepcopy(body)} if r["id"] == identifier else r for r in self.records]
            elif method == "DELETE":
                identifier = endpoint.rsplit("/", 1)[1]
                self.records = [r for r in self.records if r["id"] != identifier]
            if self.mode == "damage-unrelated":
                self.records[0]["ttlSeconds"] = 999
        if self.mode.startswith("timeout"):
            raise TimeoutError("synthetic transport loss")
        return {"_guarded_write_response": True, "status": 204, "body": None, "body_shape": "empty"}


class DnsTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)

    def mutator(self, client=None, *, identity=IDENTITY, enabled=True, identity_reader=None):
        return GuardedMutator(client or DnsClient(), site_id=identity.site_id,
                              internal_site=identity.internal_reference, controller_host=identity.controller_host,
                              site_name=identity.site_name, network_version=identity.network_version,
                              identity_reader=identity_reader or (lambda: identity),
                              env={"UNIFI_ENABLE_WRITES": WRITE_PHRASE if enabled else "disabled"},
                              snapshot_base=self.root / "snapshots", lock_path=self.root / "lock",
                              journal_base=self.root / "operations")

    def create(self, m, **kwargs):
        return m.dns_record("create", name=NAME, address=ADDRESS, **kwargs)

    def writes(self, client):
        return [c for c in client.calls if c[0] != "GET"]

    def test_pinned_versions_and_response_schema(self):
        for version in SUPPORTED_VERSIONS:
            require_version(version)
            identity = ControllerIdentity("udm.test", "site", "default", "Test Site", version)
            self.assertEqual(self.create(self.mutator(identity=identity))["mode"], "PLAN")
        for version in ("unknown", "10.6.107", "9.0.0", "10.6.106-beta"):
            with self.subTest(version=version), self.assertRaises(DnsContractError):
                require_version(version)

    def test_inspect_filters_and_only_reads(self):
        c = DnsClient([a_record(), a_record(OTHER, "other.example.test")])
        result = self.mutator(c).dns_inspect(NAME.upper() + ".")
        self.assertEqual([r["id"] for r in result["records"]], [TARGET])
        self.assertFalse(result["write_performed"])
        self.assertFalse(self.writes(c))

    def test_unknown_target_schema_refused(self):
        variants = [a_record(unrecognized=True), {**a_record(), "type": "FUTURE_RECORD"},
                    {k: v for k, v in a_record().items() if k != "metadata"},
                    {**a_record(), "metadata": {"origin": []}}]
        for record in variants:
            with self.subTest(record=record), self.assertRaises(ValidationError):
                self.create(self.mutator(DnsClient([record])))

    def test_create_one_write_known_dto_and_unrelated_preserved(self):
        c = DnsClient()
        before = copy.deepcopy(c.records)
        m = self.mutator(c)
        plan = self.create(m)["plan"]
        self.assertEqual(plan["safety_level"], 3)
        self.assertIn("NO WRITE HAS OCCURRED", plan["safety_block"]["Notice"])
        result = self.create(m, dry_run=False, approval=plan["approval_token"])
        self.assertEqual(result["mode"], "APPLIED")
        self.assertEqual(result["verification"]["resulting_id"], NEW)
        self.assertEqual(len(self.writes(c)), 1)
        self.assertEqual(self.writes(c)[0][0], "POST")
        self.assertEqual(self.writes(c)[0][2], {"type": "A_RECORD", "enabled": True,
                                              "domain": NAME, "ipv4Address": ADDRESS, "ttlSeconds": 300})
        self.assertEqual(c.records[:-1], before)
        self.assertTrue(result["verification"]["unrelated_state_unchanged"])
        self.assertFalse(result["verification"]["dns_resolution_tested"])

    def test_update_full_read_preserves_enablement_and_other_records(self):
        c = DnsClient([a_record(enabled=False), a_record(OTHER, "other.example.test")])
        original = copy.deepcopy(c.records)
        m = self.mutator(c)
        p = m.dns_record("update", identifier=TARGET, ttl=600)["plan"]
        result = m.dns_record("update", identifier=TARGET, ttl=600, dry_run=False, approval=p["approval_token"])
        self.assertEqual(result["mode"], "APPLIED")
        self.assertEqual(c.records[0], {**original[0], "ttlSeconds": 600})
        self.assertEqual(c.records[1], original[1])
        self.assertNotIn("metadata", self.writes(c)[0][2])
        self.assertNotIn("id", self.writes(c)[0][2])
        self.assertTrue(any(call[1].endswith("/" + TARGET) for call in c.calls if call[0] == "GET"))

    def test_delete_only_target(self):
        c = DnsClient([a_record(), a_record(OTHER, "other.example.test")])
        m = self.mutator(c)
        p = m.dns_record("delete", identifier=TARGET)["plan"]
        r = m.dns_record("delete", identifier=TARGET, dry_run=False, approval=p["approval_token"])
        self.assertEqual(r["mode"], "APPLIED")
        self.assertEqual(c.records, [a_record(OTHER, "other.example.test")])
        self.assertEqual(len(self.writes(c)), 1)

    def test_identical_create_and_update_noop_without_write_authorization(self):
        c = DnsClient([a_record()])
        m = self.mutator(c, enabled=False)
        self.assertEqual(self.create(m, dry_run=False)["mode"], "NO_OP")
        self.assertEqual(m.dns_record("update", identifier=TARGET, ttl=300)["mode"], "NO_OP")
        self.assertFalse(self.writes(c))
        self.assertEqual(len(list((self.root / "operations").glob("*.json"))), 2)

    def test_conflicts_duplicates_alias_and_wildcard_refused(self):
        cname = {"id": TARGET, "domain": NAME, "type": "CNAME_RECORD", "enabled": True,
                 "metadata": {"origin": "USER_DEFINED"}, "targetDomain": "other.example.test", "ttlSeconds": 300}
        variants = [[a_record(address="192.168.6.17")], [a_record(), a_record(OTHER)],
                    [a_record(), a_record()], [cname], [a_record(name="*.mcclurehomelab.duckdns.org")],
                    [{**cname, "type": "FORWARD_DOMAIN", "domain": "mcclurehomelab.duckdns.org", "ipAddress": "192.0.2.1"}]]
        for records in variants:
            with self.subTest(records=records):
                c = DnsClient(records)
                with self.assertRaises(MutationError):
                    self.create(self.mutator(c))
                self.assertFalse(self.writes(c))

    def test_protected_records_cannot_be_noop_updated_or_deleted(self):
        for origin in ("SYSTEM_DEFINED", "DERIVED", "ORCHESTRATED", "UNKNOWN"):
            for action in ("create", "update", "delete"):
                with self.subTest(origin=origin, action=action):
                    c = DnsClient([a_record(metadata={"origin": origin})])
                    m = self.mutator(c)
                    with self.assertRaises(MutationError):
                        if action == "create": self.create(m)
                        else: m.dns_record(action, identifier=TARGET, **({"ttl": 600} if action == "update" else {}))
                    self.assertFalse(self.writes(c))
        with self.assertRaises(MutationError):
            self.create(self.mutator(DnsClient([a_record(metadata={"origin": "USER_DEFINED", "configurable": False})])))

    def test_input_validation(self):
        for field, values in {"name": ["", "*.example.test", "https://host", "bad name", "bad..name", "-bad.test", "a" * 64 + ".test", "é.test", "a." * 65],
                              "address": ["::1", "invalid", "192.168.6.999", 123],
                              "ttl": [-1, 86401, True, "300", 3.5]}.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    c = DnsClient()
                    options = {"name": NAME, "address": ADDRESS, "ttl": 300, field: value}
                    with self.assertRaises(MutationError):
                        self.mutator(c).dns_record("create", **options)
                    self.assertFalse(self.writes(c))
        for ttl in (0, 86400):
            self.assertEqual(validate_a({k: v for k, v in a_record(ttlSeconds=ttl).items() if k not in {"id", "metadata"}})["ttlSeconds"], ttl)
        for identifier in ("../rest/setting", "not-a-uuid"):
            with self.assertRaises(MutationError):
                self.mutator().dns_record("delete", identifier=identifier)

    def test_missing_enablement_approval_and_changed_request_refused(self):
        c = DnsClient()
        m = self.mutator(c)
        token = self.create(m)["plan"]["approval_token"]
        for options in ({"approval": None}, {"approval": "yes"}, {"approval": token, "ttl": 600}):
            with self.assertRaises(PermissionError):
                self.create(m, dry_run=False, **options)
        with self.assertRaises(PermissionError):
            self.create(self.mutator(c, enabled=False), dry_run=False, approval=token)
        self.assertFalse(self.writes(c))

    def test_stale_approval_after_prior_plan(self):
        c = DnsClient()
        m = self.mutator(c)
        token = self.create(m)["plan"]["approval_token"]
        c.records[0]["ttlSeconds"] = 601
        with self.assertRaises(PermissionError):
            self.create(m, dry_run=False, approval=token)
        self.assertFalse(self.writes(c))

    def test_concurrent_edit_and_new_conflict_immediately_before_write(self):
        changes = [lambda c: c.records[0].update(ttlSeconds=900),
                   lambda c: c.records.append(a_record(TARGET)),
                   lambda c: c.records.append(a_record(TARGET, "*.mcclurehomelab.duckdns.org"))]
        for change in changes:
            with self.subTest(change=change):
                c = DnsClient(fresh_change=change)
                m = self.mutator(c)
                token = self.create(m)["plan"]["approval_token"]
                with self.assertRaises(StaleApprovalError):
                    self.create(m, dry_run=False, approval=token)
                self.assertFalse(self.writes(c))

    def test_detail_disagreement_and_unknown_schema_midflight_refused(self):
        c = DnsClient([a_record()])
        original = c.get_optional
        def mismatch(endpoint, **kwargs):
            result = original(endpoint, **kwargs)
            if endpoint.endswith("/" + TARGET): result["ttlSeconds"] = 999
            return result
        c.get_optional = mismatch
        with self.assertRaises(StateMismatch):
            self.mutator(c).dns_record("delete", identifier=TARGET)
        self.assertFalse(self.writes(c))

    def test_concurrent_target_edit_or_disappearance_refuses_update(self):
        changes = [lambda c: c.records[0].update(enabled=False),
                   lambda c: c.records.pop(0),
                   lambda c: c.records[0].update(unrecognized=True)]
        for change in changes:
            with self.subTest(change=change):
                c = DnsClient([a_record()], fresh_change=change)
                m = self.mutator(c)
                token = m.dns_record("update", identifier=TARGET, ttl=600)["plan"]["approval_token"]
                with self.assertRaises(StaleApprovalError):
                    m.dns_record("update", identifier=TARGET, ttl=600, dry_run=False, approval=token)
                self.assertFalse(self.writes(c))

    def test_unknown_version_mutations_fail_before_any_dns_transport(self):
        c = DnsClient()
        identity = ControllerIdentity("udm.test", "site", "default", "Test Site", "99.0.0")
        with self.assertRaises(ValidationError):
            self.create(self.mutator(c, identity=identity))
        self.assertFalse(c.calls)

    def test_identity_bound_approval_and_midflight_identity_checks(self):
        for field in ("controller_host", "site_id", "internal_reference", "site_name", "network_version"):
            with self.subTest(field=field):
                c = DnsClient()
                m = self.mutator(c)
                token = self.create(m)["plan"]["approval_token"]
                changed = ControllerIdentity(**{**IDENTITY.as_dict(), field: "10.5.67" if field == "network_version" else "changed"})
                m.identity_reader = mock.Mock(side_effect=[IDENTITY, changed])
                with self.assertRaises(StaleApprovalError):
                    self.create(m, dry_run=False, approval=token)
                self.assertFalse(self.writes(c))
                self.assertNotEqual(self.create(self.mutator(DnsClient(), identity=changed))["plan"]["approval_token"], token)

    def test_collection_order_does_not_change_token(self):
        c = DnsClient([a_record(OTHER, "other.test"), a_record(TARGET, "third.test")])
        m = self.mutator(c)
        token = self.create(m)["plan"]["approval_token"]
        c.records.reverse()
        self.assertEqual(self.create(m)["plan"]["approval_token"], token)

    def test_ambiguous_response_get_only_reconciliation_no_retry(self):
        for mode in ("normal", "timeout-applied", "delayed"):
            with self.subTest(mode=mode), mock.patch("mutationlib.time.sleep"):
                c = DnsClient(mode=mode)
                m = self.mutator(c)
                p = self.create(m)["plan"]
                self.assertEqual(self.create(m, dry_run=False, approval=p["approval_token"])["mode"], "APPLIED")
                writes = self.writes(c)
                self.assertEqual(len(writes), 1)
                write_at = next(i for i, call in enumerate(c.calls) if call[0] != "GET")
                self.assertTrue(all(call[0] == "GET" for call in c.calls[write_at + 1:]))

    def test_unresolved_ambiguous_outcomes_and_unrelated_damage(self):
        for mode in ("timeout-none", "duplicate", "damage-unrelated"):
            with self.subTest(mode=mode), mock.patch("mutationlib.time.sleep"):
                c = DnsClient(mode=mode)
                m = self.mutator(c)
                token = self.create(m)["plan"]["approval_token"]
                with self.assertRaises(AmbiguousWriteError) as error:
                    self.create(m, dry_run=False, approval=token)
                self.assertTrue(error.exception.details["write_performed"])
                self.assertEqual(len(self.writes(c)), 1)

    def test_update_and_delete_lost_responses_reconcile_with_one_write(self):
        for action in ("update", "delete"):
            with self.subTest(action=action):
                c = DnsClient([a_record()], mode="timeout-applied")
                m = self.mutator(c)
                kwargs = {"ttl": 600} if action == "update" else {}
                p = m.dns_record(action, identifier=TARGET, **kwargs)["plan"]
                result = m.dns_record(action, identifier=TARGET, dry_run=False, approval=p["approval_token"], **kwargs)
                self.assertEqual(result["mode"], "APPLIED")
                self.assertEqual(len(self.writes(c)), 1)

    def test_postwrite_get_failure_stops_ambiguous_without_retry(self):
        c = DnsClient()
        m = self.mutator(c)
        token = self.create(m)["plan"]["approval_token"]
        getter = c.get_optional
        def failed_read(endpoint, **kwargs):
            if self.writes(c):
                raise TimeoutError("synthetic read failure")
            return getter(endpoint, **kwargs)
        c.get_optional = failed_read
        with mock.patch("mutationlib.time.sleep"), self.assertRaises(AmbiguousWriteError):
            self.create(m, dry_run=False, approval=token)
        self.assertEqual(len(self.writes(c)), 1)

    def test_definitive_rejection_is_not_retried(self):
        c = DnsClient(mode="rejected")
        m = self.mutator(c)
        token = self.create(m)["plan"]["approval_token"]
        with mock.patch("mutationlib.time.sleep"):
            self.assertEqual(self.create(m, dry_run=False, approval=token)["mode"], "NOT_APPLIED")
        self.assertEqual(len(self.writes(c)), 1)

    def test_snapshot_integrity_and_private_journal(self):
        c = DnsClient()
        p = self.create(self.mutator(c))["plan"]
        folder = Path(p["snapshot_path"])
        manifest, saved = load_snapshot(folder, expected_type="dns-record", expected_identity=IDENTITY.as_dict())
        self.assertEqual(saved["records"], c.records)
        self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
        journal = Path(p["operation_record"]).read_text()
        self.assertNotIn(p["approval_token"], journal)
        self.assertNotIn("approval_token", journal)
        for file in folder.glob("*.json"):
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        (folder / manifest["files"][0]).write_text("{}")
        with self.assertRaises(SnapshotError):
            self.mutator(c).dns_record("restore", snapshot_path=folder, identifier=NEW)

    def test_gate_rechecks_snapshot_integrity_before_write(self):
        c = DnsClient()
        m = self.mutator(c)
        token = self.create(m)["plan"]["approval_token"]
        original = m._snapshot
        def corrupt(*args, **kwargs):
            folder = original(*args, **kwargs)
            payload = next(file for file in folder.glob("*.json") if file.name != "manifest.json")
            payload.write_text("{}")
            return folder
        with mock.patch.object(m, "_snapshot", side_effect=corrupt), self.assertRaises(PermissionError):
            self.create(m, dry_run=False, approval=token)
        self.assertFalse(self.writes(c))

    def test_rollback_create_requires_resulting_id_and_separate_approval(self):
        c = DnsClient()
        m = self.mutator(c)
        p = self.create(m)["plan"]
        self.create(m, dry_run=False, approval=p["approval_token"])
        with self.assertRaises(StateMismatch):
            m.dns_record("restore", snapshot_path=Path(p["snapshot_path"]))
        rollback = m.dns_record("restore", snapshot_path=Path(p["snapshot_path"]), identifier=NEW)["plan"]
        self.assertNotEqual(rollback["approval_token"], p["approval_token"])
        with self.assertRaises(PermissionError):
            m.dns_record("restore", snapshot_path=Path(p["snapshot_path"]), identifier=NEW,
                         dry_run=False, approval=p["approval_token"])
        result = m.dns_record("restore", snapshot_path=Path(p["snapshot_path"]), identifier=NEW,
                              dry_run=False, approval=rollback["approval_token"])
        self.assertEqual(result["mode"], "APPLIED")
        self.assertEqual(c.records, [a_record(OTHER, "other.example.test")])
        self.assertTrue(json.loads(Path(result["plan"]["operation_record"]).read_text())["rollback_attempted"])

    def test_rollback_update_and_delete_preserve_unrelated_new_records(self):
        for action in ("update", "delete"):
            with self.subTest(action=action):
                c = DnsClient([a_record(), a_record(OTHER, "other.example.test")])
                m = self.mutator(c)
                options = {"ttl": 600} if action == "update" else {}
                p = m.dns_record(action, identifier=TARGET, **options)["plan"]
                m.dns_record(action, identifier=TARGET, **options, dry_run=False, approval=p["approval_token"])
                new_unrelated = a_record("44444444-4444-4444-8444-444444444444", "new.example.test")
                c.records.append(new_unrelated)
                r = m.dns_record("restore", snapshot_path=Path(p["snapshot_path"]))["plan"]
                result = m.dns_record("restore", snapshot_path=Path(p["snapshot_path"]),
                                      dry_run=False, approval=r["approval_token"])
                self.assertEqual(result["mode"], "APPLIED")
                restored = next(x for x in c.records if x["domain"] == NAME)
                self.assertEqual(restored["ttlSeconds"], 300)
                self.assertIn(new_unrelated, c.records)
                self.assertEqual(result["verification"]["original_id"], TARGET)

    def test_rollback_requires_write_enablement_and_new_approval(self):
        c = DnsClient([a_record()])
        m = self.mutator(c)
        p = m.dns_record("delete", identifier=TARGET)["plan"]
        m.dns_record("delete", identifier=TARGET, dry_run=False, approval=p["approval_token"])
        restore = m.dns_record("restore", snapshot_path=Path(p["snapshot_path"]))["plan"]
        for enabled, approval in ((False, restore["approval_token"]), (True, None), (True, p["approval_token"])):
            with self.subTest(enabled=enabled, approval=approval), self.assertRaises(PermissionError):
                self.mutator(c, enabled=enabled).dns_record("restore", snapshot_path=Path(p["snapshot_path"]),
                                                         dry_run=False, approval=approval)
        self.assertEqual(len(self.writes(c)), 1)

    def test_rollback_delete_refuses_new_owner_conflict(self):
        c = DnsClient([a_record()])
        m = self.mutator(c)
        p = m.dns_record("delete", identifier=TARGET)["plan"]
        m.dns_record("delete", identifier=TARGET, dry_run=False, approval=p["approval_token"])
        c.records.append(a_record(OTHER, NAME, "192.168.6.99"))
        with self.assertRaises(StateMismatch):
            m.dns_record("restore", snapshot_path=Path(p["snapshot_path"]))
        self.assertEqual(len(self.writes(c)), 1)

    def test_restore_changed_target_wrong_identity_and_sensitive_snapshot_refused(self):
        c = DnsClient([a_record()])
        m = self.mutator(c)
        p = m.dns_record("update", identifier=TARGET, ttl=600)["plan"]
        m.dns_record("update", identifier=TARGET, ttl=600, dry_run=False, approval=p["approval_token"])
        c.records[0]["ttlSeconds"] = 900
        with self.assertRaises(StateMismatch):
            m.dns_record("restore", snapshot_path=Path(p["snapshot_path"]))
        identity = ControllerIdentity("other.test", "site", "default", "Test Site", "10.6.106")
        with self.assertRaises(SnapshotError):
            self.mutator(c, identity=identity).dns_record("restore", snapshot_path=Path(p["snapshot_path"]))
        c = DnsClient([a_record(OTHER, "other.test"), {"id": TARGET, "type": "TXT_RECORD", "enabled": True,
                                                    "domain": "txt.test", "text": "text", "metadata": {"origin": "USER_DEFINED"}, "secret": "hidden"}])
        with self.assertRaises(MutationError):
            self.create(self.mutator(c))

    def test_cli_routes_to_guarded_engine(self):
        c = DnsClient()
        env = {"UDM_HOST": "udm.test", "UNIFI_API_KEY": "synthetic-not-a-key"}
        with mock.patch.object(mutate, "load_env", return_value=env), \
             mock.patch.dict(sys.modules, {"udm": mock.Mock(UDMClient=mock.Mock(return_value=c))}), \
             mock.patch.object(mutate, "GuardedMutator", return_value=self.mutator(c)), \
             mock.patch.object(sys, "argv", ["mutate.py", "dns", "create", "--name", NAME, "--ip", ADDRESS, "--plan"]), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            mutate.main()
        self.assertEqual(json.loads(output.getvalue())["mode"], "PLAN")
        self.assertFalse(self.writes(c))

    def test_cli_reports_attempted_write_after_ambiguity(self):
        c = DnsClient()
        m = self.mutator(c)
        m.dns_record = mock.Mock(side_effect=AmbiguousWriteError("ambiguous", {"write_performed": True}))
        with mock.patch.object(mutate, "load_env", return_value={"UDM_HOST": "udm.test", "UNIFI_API_KEY": "synthetic"}), \
             mock.patch.dict(sys.modules, {"udm": mock.Mock(UDMClient=mock.Mock(return_value=c))}), \
             mock.patch.object(mutate, "GuardedMutator", return_value=m), \
             mock.patch.object(sys, "argv", ["mutate.py", "dns", "create", "--name", NAME, "--ip", ADDRESS, "--approve", "token"]), \
             self.assertRaises(SystemExit) as error:
            mutate.main()
        self.assertTrue(json.loads(str(error.exception))["write_performed"])


class DnsInventoryTests(unittest.TestCase):
    def test_complete_paginated_collection(self):
        records = [a_record(), a_record(OTHER, "other.test")]
        calls = []
        def get(endpoint):
            calls.append(endpoint)
            offset = len(calls) - 1
            return page([records[offset]], offset, 2)
        self.assertEqual(fetch_records(get, "/dns/policies"), records)
        self.assertIn("offset=1", calls[1])

    def test_unknown_incomplete_and_nonprogressing_pages_refused(self):
        for value in (None, [], {"data": []}, page([], total=1), {**page([]), "count": True},
                      {**page([]), "totalCount": 10001}, {**page([]), "offset": 10}, page([{}])):
            with self.subTest(value=value), self.assertRaises(DnsContractError):
                fetch_records(lambda _: value, "/dns/policies")

    def test_changing_total_midpagination_refused(self):
        get = mock.Mock(side_effect=[page([a_record()], total=2), page([a_record(OTHER, "other.test")], offset=1, total=3)])
        with self.assertRaises(DnsContractError):
            fetch_records(get, "/dns/policies")

    def test_inventory_and_plan_show_official_dns_and_unknown_version_unavailable(self):
        class InventoryClient(FakeClient):
            version = "10.6.106"
            def get_optional(self, url, *, unwrap=True):
                if url.endswith("/integration/v1/info"):
                    return {"applicationVersion": self.version}
                if "/dns/policies" in url:
                    self.calls.append(("GET", url, self.site))
                    return page([a_record()])
                return super().get_optional(url, unwrap=unwrap)
        client = InventoryClient([site()])
        data = collect_inventory(client)
        self.assertEqual(data["dns_records"], [a_record()])
        self.assertEqual(data["collection_status"]["dns_records"]["status"], "available")
        client.version = "99.0.0"
        data = collect_inventory(client)
        self.assertIsNone(data["dns_records"])
        self.assertEqual(data["collection_status"]["dns_records"]["status"], "unavailable")
        requests = [r for s in build_plan()["stages"] for r in s["requests"]]
        self.assertTrue(any(r["dataset"] == "dns_records" and r["method"] == "GET" for r in requests))

    def test_inventory_unsupported_endpoint_or_schema_remains_unavailable(self):
        for value in ({"data": []}, {"_unavailable": True}, page([{"record_type": "A", "key": NAME}])):
            with self.subTest(value=value):
                c = FakeClient([site()])
                getter = c.get_optional
                c.get_optional = lambda url, **kwargs: value if "/dns/policies" in url else getter(url, **kwargs)
                inventory = collect_inventory(c)
                self.assertIsNone(inventory["dns_records"])
                self.assertEqual(inventory["collection_status"]["dns_records"]["status"], "unavailable")
                self.assertIsNotNone(inventory["networks"])


class DnsResolutionTests(unittest.TestCase):
    def test_expected_ip_verification_uses_client_resolver(self):
        row = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ADDRESS, 443))
        with mock.patch("verify_network.tcp", return_value=True), mock.patch("verify_network.socket.getaddrinfo", return_value=[row]) as resolver:
            result = verify("udm.test", NAME, expected_ip=ADDRESS)
        self.assertTrue(result["verified"])
        self.assertEqual(result["dns_ipv4_addresses"], [ADDRESS])
        resolver.assert_called_once_with(NAME, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)

    def test_wrong_multiple_or_missing_answers_fail(self):
        rows = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443)) for ip in (ADDRESS, "192.168.6.17")]
        for answer in ([], rows, rows[1:]):
            with mock.patch("verify_network.tcp", return_value=True), mock.patch("verify_network.socket.getaddrinfo", return_value=answer):
                self.assertFalse(verify("udm.test", NAME, expected_ip=ADDRESS)["verified"])
        with mock.patch("verify_network.tcp", return_value=True), mock.patch("verify_network.socket.getaddrinfo", side_effect=socket.gaierror):
            self.assertFalse(verify("udm.test", NAME, expected_ip=ADDRESS)["verified"])


if __name__ == "__main__":
    unittest.main()
