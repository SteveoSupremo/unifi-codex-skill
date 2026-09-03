import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))

from mutationlib import (AmbiguousWriteError, ControllerIdentity, GuardedMutator,
                         StaleApprovalError, StateMismatch, ValidationError)
from snapshot import SnapshotError, _write_private, create_snapshot
from unifi_common import WRITE_PHRASE


TEST_IDENTITY = {"controller_host": "udm.test", "site_id": "site",
                 "internal_reference": "default", "site_name": "Test Site",
                 "network_version": "10.5.67"}


def policy(identifier="user-1", origin="USER_DEFINED", name="Allow DNS"):
    return {"id": identifier, "name": name, "enabled": True, "index": 100,
            "action": {"type": "ALLOW", "allowReturnTraffic": False},
            "source": {"zoneId": "zone-media"},
            "destination": {"zoneId": "zone-gateway"},
            "ipProtocolScope": {"ipVersion": "IPV4", "protocolFilter": "UDP"},
            "connectionStateFilter": ["NEW"],
            "metadata": {"origin": origin, "configurable": origin == "USER_DEFINED"}}


class FakeMutationClient:
    base = ""

    def __init__(self):
        self.calls = []
        self.port_forwards = [
            {"_id": "pf-target", "name": "HomeProxMox", "fwd": "192.168.6.10", "dst_port": "8006", "enabled": True},
            {"_id": "pf-other", "name": "HTTPS", "fwd": "192.168.6.20", "dst_port": "443", "enabled": True},
        ]
        self.policies = [
            {"id": "generated-pf", "name": "Allow Port Forward HomeProxMox", "portForwardId": "pf-target",
             "source": {"zoneId": "zone-external"}, "destination": {"zoneId": "zone-servers"},
             "metadata": {"origin": "SYSTEM_DEFINED", "configurable": False}},
            policy(),
        ]
        self.forwarding_status = [
            {"id": "status-pf", "portForwardId": "pf-target", "name": "HomeProxMox", "fwd": "192.168.6.10", "dst_port": "8006"},
            {"id": "status-other", "portForwardId": "pf-other", "name": "HTTPS", "fwd": "192.168.6.20", "dst_port": "443"},
        ]
        self.zones = [{"id": "zone-media", "name": "Media", "networkIds": ["net-media"]},
                      {"id": "zone-gateway", "name": "Gateway", "networkIds": []},
                      {"id": "zone-external", "name": "External", "networkIds": []},
                      {"id": "zone-servers", "name": "Servers", "networkIds": []}]
        self.networks = [{"_id": "net-media", "id": "net-media", "name": "Media", "vlan": 5,
                          "ip_subnet": "192.168.7.1/24", "dhcpd_start": "192.168.7.20", "dhcpd_stop": "192.168.7.200"}]
        self.users = [{"_id": "client-apple", "name": "Apple TV", "mac": "50:32:37:b2:f2:9a",
                       "network_id": "net-media", "use_fixedip": False, "note": "preserve"},
                      {"_id": "client-other", "name": "Other", "mac": "aa:bb:cc:dd:ee:ff",
                       "network_id": "net-media", "use_fixedip": True, "fixed_ip": "192.168.7.80"}]
        self.active = [{"mac": "50:32:37:b2:f2:9a", "ip": "192.168.7.59", "network_id": "net-media"}]

    @staticmethod
    def _copy(value):
        return copy.deepcopy(value)

    def get(self, endpoint):
        self.calls.append(("GET", endpoint))
        clean = endpoint.split("?", 1)[0]
        if clean.endswith("/rest/portforward"):
            return self._copy(self.port_forwards)
        if "/rest/portforward/" in clean:
            identifier = clean.rsplit("/", 1)[1]
            return self._copy([item for item in self.port_forwards if item.get("_id") == identifier])
        if clean.endswith("/firewall/policies"):
            return self._copy(self.policies)
        if "/firewall/policies/" in clean:
            identifier = clean.rsplit("/", 1)[1]
            return self._copy([item for item in self.policies if item.get("id") == identifier])
        if clean.endswith("/firewall/zones"):
            return self._copy(self.zones)
        if clean.endswith("/integration/v1/sites/site/networks"):
            return self._copy(self.networks)
        if clean.endswith("/stat/portforward"):
            return self._copy(self.forwarding_status)
        if clean.endswith("/rest/user"):
            return self._copy(self.users)
        if "/rest/user/" in clean:
            identifier = clean.rsplit("/", 1)[1]
            return self._copy([item for item in self.users if item.get("_id") == identifier])
        if clean.endswith("/stat/sta"):
            return self._copy(self.active)
        if clean.endswith("/rest/networkconf"):
            return self._copy(self.networks)
        raise AssertionError(f"unexpected GET {endpoint}")

    def delete(self, endpoint):
        self.calls.append(("DELETE", endpoint))
        identifier = endpoint.rsplit("/", 1)[1]
        if "/rest/portforward/" in endpoint:
            self.port_forwards = [item for item in self.port_forwards if item.get("_id") != identifier]
            self.policies = [item for item in self.policies if item.get("portForwardId") != identifier]
            self.forwarding_status = [item for item in self.forwarding_status if item.get("portForwardId") != identifier]
        else:
            self.policies = [item for item in self.policies if item.get("id") != identifier]
        return {}

    def post(self, endpoint, body):
        self.calls.append(("POST", endpoint, self._copy(body)))
        if endpoint.endswith("/rest/portforward"):
            created = self._copy(body)
            created["_id"] = "pf-restored"
            self.port_forwards.append(created)
            self.policies.append({"id": "generated-restored", "name": "Allow Port Forward " + str(created.get("name")),
                                  "portForwardId": "pf-restored", "fwd": created.get("fwd"), "dst_port": created.get("dst_port"),
                                  "source": {"zoneId": "zone-external"}, "destination": {"zoneId": "zone-servers"},
                                  "metadata": {"origin": "SYSTEM_DEFINED", "configurable": False}})
            self.forwarding_status.append({"id": "status-restored", "portForwardId": "pf-restored", "name": created.get("name"),
                                           "fwd": created.get("fwd"), "dst_port": created.get("dst_port")})
            return [self._copy(created)]
        created = self._copy(body)
        created["id"] = "user-created"
        self.policies.append(created)
        return [self._copy(created)]

    def put(self, endpoint, body):
        self.calls.append(("PUT", endpoint, self._copy(body)))
        identifier = endpoint.rsplit("/", 1)[1]
        if "/rest/user/" in endpoint:
            self.users = [self._copy(body) if item.get("_id") == identifier else item for item in self.users]
            return [self._copy(body)]
        self.policies = [self._copy(body) if item.get("id") == identifier else item for item in self.policies]
        return [self._copy(body)]


class MutationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def mutator(self, client=None, env=None):
        return GuardedMutator(client or FakeMutationClient(), site_id="site", internal_site="default",
                              env=env or {"UNIFI_ENABLE_WRITES": "disabled"},
                              snapshot_base=self.base / "snapshots", lock_path=self.base / "mutation.lock",
                              journal_base=self.base / "operations", controller_host="udm.test",
                              site_name="Test Site", network_version="10.5.67",
                              identity_reader=lambda: ControllerIdentity(**TEST_IDENTITY))

    def plan_delete(self, mutator):
        return mutator.port_forward_delete("pf-target", dry_run=True)["plan"]

    def test_central_layer_requires_authoritative_identity_reader(self):
        with self.assertRaisesRegex(ValidationError, "identity reader"):
            GuardedMutator(FakeMutationClient(), site_id="site", internal_site="default",
                           controller_host="udm.test", site_name="Test Site",
                           network_version="10.5.67")

    def test_write_gate_disabled(self):
        mutator = self.mutator()
        token = self.plan_delete(mutator)["approval_token"]
        self.assertTrue(token.startswith("DELETE-PF-pf-targe-"))
        with self.assertRaises(PermissionError):
            mutator.port_forward_delete("pf-target", dry_run=False, approval=token)

    def test_wrong_enablement_phrase(self):
        mutator = self.mutator(env={"UNIFI_ENABLE_WRITES": "I_UNDERSTAND"})
        token = self.plan_delete(mutator)["approval_token"]
        with self.assertRaises(PermissionError):
            mutator.port_forward_delete("pf-target", dry_run=False, approval=token)

    def test_no_explicit_approval(self):
        mutator = self.mutator(env={"UNIFI_ENABLE_WRITES": WRITE_PHRASE})
        with self.assertRaises(PermissionError):
            mutator.port_forward_delete("pf-target", dry_run=False)

    def test_current_state_mismatch(self):
        with self.assertRaises(StateMismatch):
            self.mutator().port_forward_delete("pf-target", expected={"name": "Wrong"}, dry_run=True)

    def test_snapshot_failure_stops_before_write(self):
        client = FakeMutationClient()
        with mock.patch("mutationlib.create_snapshot", side_effect=SnapshotError("unable to write rollback snapshot")):
            with self.assertRaisesRegex(Exception, "snapshot"):
                self.mutator(client).port_forward_delete("pf-target", dry_run=True)
        self.assertFalse(any(call[0] in {"POST", "PUT", "DELETE"} for call in client.calls))

    def test_validation_failure(self):
        client = FakeMutationClient()
        client.port_forwards[0] = {"_id": "pf-target"}
        with self.assertRaises(ValidationError):
            self.mutator(client).port_forward_delete("pf-target", dry_run=True)

    def test_successful_port_forward_delete_and_generated_disappearance(self):
        client = FakeMutationClient()
        mutator = self.mutator(client, {"UNIFI_ENABLE_WRITES": WRITE_PHRASE})
        token = self.plan_delete(mutator)["approval_token"]
        result = mutator.port_forward_delete("pf-target", dry_run=False, approval=token)
        self.assertTrue(result["verification"]["target_disappeared"])
        self.assertTrue(result["verification"]["generated_policy_disappeared"])
        self.assertTrue(result["verification"]["forwarding_status_disappeared"])
        self.assertTrue(result["verification"]["unrelated_forwards_unchanged"])
        self.assertEqual([item["_id"] for item in client.port_forwards], ["pf-other"])
        self.assertEqual(sum(call[0] == "DELETE" for call in client.calls), 1)
        self.assertEqual(result["completion_block"]["Authoritative write count"], 1)
        journal = json.loads(Path(result["plan"]["operation_record"]).read_text(encoding="utf-8"))
        self.assertEqual(journal["result"], "APPLIED_VERIFIED")
        self.assertEqual(journal["authoritative_write_count"], 1)
        self.assertFalse(journal["rollback_attempted"])

    def test_restore_from_snapshot_and_id_change(self):
        client = FakeMutationClient()
        original = client.port_forwards.pop(0)
        client.policies = [item for item in client.policies if item.get("portForwardId") != "pf-target"]
        client.forwarding_status = [item for item in client.forwarding_status if item.get("portForwardId") != "pf-target"]
        source = create_snapshot("unifi-network", "port-forward", "pf-target", original, "test deletion",
                                 base=self.base / "source", restorable=True, controller_identity=TEST_IDENTITY)
        mutator = self.mutator(client, {"UNIFI_ENABLE_WRITES": WRITE_PHRASE})
        token = mutator.port_forward_restore(source, dry_run=True)["plan"]["approval_token"]
        result = mutator.port_forward_restore(source, dry_run=False, approval=token)
        self.assertTrue(result["verification"]["verified"])
        self.assertTrue(result["verification"]["id_changed"])
        self.assertEqual(result["verification"]["new_id"], "pf-restored")

    def test_rollback_requires_separate_approval(self):
        client = FakeMutationClient()
        original = client.port_forwards.pop(0)
        client.policies = [item for item in client.policies if item.get("portForwardId") != "pf-target"]
        client.forwarding_status = [item for item in client.forwarding_status if item.get("portForwardId") != "pf-target"]
        source = create_snapshot("unifi-network", "port-forward", "pf-target", original, "test deletion",
                                 base=self.base / "source", restorable=True, controller_identity=TEST_IDENTITY)
        mutator = self.mutator(client, {"UNIFI_ENABLE_WRITES": WRITE_PHRASE})
        delete_token = "APPROVE-00000000000000000000"
        with self.assertRaises(PermissionError):
            mutator.port_forward_restore(source, dry_run=False, approval=delete_token)
        self.assertFalse(any(call[0] == "POST" for call in client.calls))

    def test_restore_rejects_tampered_snapshot(self):
        client = FakeMutationClient()
        original = client.port_forwards.pop(0)
        source = create_snapshot("unifi-network", "port-forward", "pf-target", original, "test deletion",
                                 base=self.base / "source", restorable=True, controller_identity=TEST_IDENTITY)
        next(source.glob("port-forward-*.json")).write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(SnapshotError, "integrity"):
            self.mutator(client).port_forward_restore(source, dry_run=True)

    def test_refuses_system_defined_and_derived_policy_delete(self):
        for origin in ("SYSTEM_DEFINED", "DERIVED"):
            with self.subTest(origin=origin):
                client = FakeMutationClient()
                client.policies.append(policy("protected", origin, "Protected"))
                with self.assertRaises(PermissionError):
                    self.mutator(client).firewall_policy_delete("protected", dry_run=True)
                self.assertFalse(any(call[0] == "DELETE" for call in client.calls))

    def test_fixed_ip_conflict_detection(self):
        with self.assertRaisesRegex(ValidationError, "reservation"):
            self.mutator().fixed_ip_change("50:32:37:b2:f2:9a", "192.168.7.80", dry_run=True)

    def test_fixed_ip_plan_preserves_unrelated_settings(self):
        result = self.mutator().fixed_ip_change("50:32:37:b2:f2:9a", "192.168.7.60", dry_run=True)
        self.assertEqual(result["plan"]["proposed_state"]["note"], "preserve")
        self.assertTrue(result["plan"]["proposed_state"]["use_fixedip"])
        self.assertEqual(result["plan"]["safety_level"], 3)
        self.assertTrue(any("inside_dynamic_pool" in step for step in result["plan"]["validation_steps"]))
        self.assertTrue(any("reservations may be inside or outside" in step for step in result["plan"]["validation_steps"]))

    def test_firewall_create_update_delete_dry_run(self):
        cases = [
            ("create", lambda m: m.firewall_policy_create(policy("input"), dry_run=True)),
            ("update", lambda m: m.firewall_policy_update("user-1", {"name": "Updated", "action": {"type": "BLOCK"}}, dry_run=True)),
            ("delete", lambda m: m.firewall_policy_delete("user-1", dry_run=True)),
        ]
        for name, operation in cases:
            with self.subTest(action=name):
                client = FakeMutationClient()
                result = operation(self.mutator(client))
                self.assertEqual(result["mode"], "PLAN")
                self.assertFalse(result["write_performed"])
                self.assertFalse(any(call[0] in {"POST", "PUT", "DELETE"} for call in client.calls))
                self.assertTrue(result["plan"]["diff"])
                if name == "create":
                    self.assertNotIn("id", result["plan"]["proposed_state"])
                if name == "update":
                    self.assertFalse(result["plan"]["proposed_state"]["action"]["allowReturnTraffic"])

    def test_approval_token_cannot_authorize_modified_diff(self):
        client = FakeMutationClient()
        mutator = self.mutator(client, {"UNIFI_ENABLE_WRITES": WRITE_PHRASE})
        token = mutator.firewall_policy_update("user-1", {"name": "Plan A"}, dry_run=True)["plan"]["approval_token"]
        with self.assertRaises(PermissionError):
            mutator.firewall_policy_update("user-1", {"name": "Plan B"}, dry_run=False, approval=token)
        self.assertFalse(any(call[0] == "PUT" for call in client.calls))

    def test_toctou_target_change_after_approval_is_refused(self):
        class ChangingClient(FakeMutationClient):
            def __init__(self):
                super().__init__()
                self.item_reads = 0

            def get(self, endpoint):
                if "/rest/portforward/pf-target" in endpoint:
                    self.item_reads += 1
                    if self.item_reads == 3:
                        self.port_forwards[0]["dst_port"] = "9999"
                return super().get(endpoint)

        client = ChangingClient()
        mutator = self.mutator(client, {"UNIFI_ENABLE_WRITES": WRITE_PHRASE})
        token = self.plan_delete(mutator)["approval_token"]
        with self.assertRaisesRegex(StaleApprovalError, "Approved state is stale"):
            mutator.port_forward_delete("pf-target", dry_run=False, approval=token)
        self.assertFalse(any(call[0] == "DELETE" for call in client.calls))

    def test_wrong_controller_snapshot_is_refused(self):
        for field, value in (("controller_host", "different-udm.test"), ("site_id", "different-site")):
            with self.subTest(field=field):
                client = FakeMutationClient()
                original = client.port_forwards.pop(0)
                wrong = dict(TEST_IDENTITY, **{field: value})
                source = create_snapshot("unifi-network", "port-forward", "pf-target", original, "test deletion",
                                         base=self.base / field, restorable=True, controller_identity=wrong)
                with self.assertRaisesRegex(SnapshotError, "different controller or site"):
                    self.mutator(client).port_forward_restore(source, dry_run=True)

    def test_controller_identity_change_immediately_before_write_is_refused(self):
        client = FakeMutationClient()
        mutator = self.mutator(client, {"UNIFI_ENABLE_WRITES": WRITE_PHRASE})
        token = self.plan_delete(mutator)["approval_token"]
        mutator.identity_reader = lambda: ControllerIdentity("other.test", "site", "default", "Test Site", "10.5.67")
        with self.assertRaisesRegex(StaleApprovalError, "identity changed"):
            mutator.port_forward_delete("pf-target", dry_run=False, approval=token)
        self.assertFalse(any(call[0] == "DELETE" for call in client.calls))

    def test_ambiguous_delete_is_not_retried(self):
        class AmbiguousDeleteClient(FakeMutationClient):
            def delete(self, endpoint):
                self.calls.append(("DELETE", endpoint))
                raise TimeoutError("response lost")

        client = AmbiguousDeleteClient()
        mutator = self.mutator(client, {"UNIFI_ENABLE_WRITES": WRITE_PHRASE})
        token = self.plan_delete(mutator)["approval_token"]
        with self.assertRaises(AmbiguousWriteError):
            mutator.port_forward_delete("pf-target", dry_run=False, approval=token)
        self.assertEqual(sum(call[0] == "DELETE" for call in client.calls), 1)

    def test_restore_timeout_reconciles_success_without_retry(self):
        class AppliedThenTimedOutClient(FakeMutationClient):
            def post(self, endpoint, body):
                super().post(endpoint, body)
                raise TimeoutError("response lost after transmission")

        client = AppliedThenTimedOutClient()
        original = client.port_forwards.pop(0)
        client.policies = [item for item in client.policies if item.get("portForwardId") != "pf-target"]
        client.forwarding_status = [item for item in client.forwarding_status if item.get("portForwardId") != "pf-target"]
        source = create_snapshot("unifi-network", "port-forward", "pf-target", original, "test deletion",
                                 base=self.base / "source", restorable=True, controller_identity=TEST_IDENTITY)
        mutator = self.mutator(client, {"UNIFI_ENABLE_WRITES": WRITE_PHRASE})
        token = mutator.port_forward_restore(source, dry_run=True)["plan"]["approval_token"]
        result = mutator.port_forward_restore(source, dry_run=False, approval=token)
        self.assertEqual(result["mode"], "RECONCILED_APPLIED_AFTER_AMBIGUOUS_RESPONSE")
        self.assertEqual(sum(call[0] == "POST" for call in client.calls), 1)
        self.assertTrue(result["verification"]["semantic_restoration"])

    def test_snapshot_is_immutable_and_identity_bound(self):
        client = FakeMutationClient()
        plan = self.plan_delete(self.mutator(client))
        folder = Path(plan["snapshot_path"])
        manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["controller_identity"], TEST_IDENTITY)
        self.assertIn("snapshot_sha256", manifest)
        self.assertIn("timestamp", manifest)
        with self.assertRaisesRegex(SnapshotError, "immutable"):
            _write_private(folder / manifest["files"][0], {"changed": True})

    def test_operation_journal_is_sanitized_and_records_plan(self):
        plan = self.plan_delete(self.mutator())
        record_path = Path(plan["operation_record"])
        record_text = record_path.read_text(encoding="utf-8")
        record = json.loads(record_text)
        self.assertEqual(record["result"], "PLANNED_NO_WRITE")
        self.assertEqual(record["authoritative_write_count"], 0)
        self.assertEqual(record["controller_identity"], TEST_IDENTITY)
        self.assertIn("approval_fingerprint", record)
        self.assertNotIn("approval_token", record_text)
        self.assertTrue(plan["safety_block"]["Notice"].startswith("NO WRITE"))

    def test_firewall_unrelated_order_change_is_detected(self):
        class ReorderingClient(FakeMutationClient):
            def put(self, endpoint, body):
                result = super().put(endpoint, body)
                self.policies.reverse()
                return result

        client = ReorderingClient()
        client.policies.append(policy("user-2", name="Second"))
        mutator = self.mutator(client, {"UNIFI_ENABLE_WRITES": WRITE_PHRASE})
        token = mutator.firewall_policy_update("user-1", {"name": "Updated"}, dry_run=True)["plan"]["approval_token"]
        with self.assertRaisesRegex(Exception, "verification failed"):
            mutator.firewall_policy_update("user-1", {"name": "Updated"}, dry_run=False, approval=token)
        self.assertEqual(sum(call[0] == "PUT" for call in client.calls), 1)

    def test_fixed_ip_conflict_with_active_lease(self):
        client = FakeMutationClient()
        client.active.append({"mac": "11:22:33:44:55:66", "ip": "192.168.7.70", "network_id": "net-media"})
        with self.assertRaisesRegex(ValidationError, "currently assigned"):
            self.mutator(client).fixed_ip_change("50:32:37:b2:f2:9a", "192.168.7.70", dry_run=True)

    def test_fixed_ip_target_network_change_before_write_is_refused(self):
        class MovingClient(FakeMutationClient):
            def __init__(self):
                super().__init__()
                self.networks.append({"_id": "net-other", "id": "net-other", "name": "Other", "vlan": 9,
                                      "ip_subnet": "192.168.9.1/24", "dhcpd_start": "192.168.9.20", "dhcpd_stop": "192.168.9.200"})
                self.item_reads = 0

            def get(self, endpoint):
                if "/rest/user/client-apple" in endpoint:
                    self.item_reads += 1
                    if self.item_reads == 3:
                        self.users[0]["network_id"] = "net-other"
                return super().get(endpoint)

        client = MovingClient()
        mutator = self.mutator(client, {"UNIFI_ENABLE_WRITES": WRITE_PHRASE})
        token = mutator.fixed_ip_change("50:32:37:b2:f2:9a", "192.168.7.60", dry_run=True)["plan"]["approval_token"]
        with self.assertRaises(StaleApprovalError):
            mutator.fixed_ip_change("50:32:37:b2:f2:9a", "192.168.7.60", dry_run=False, approval=token)
        self.assertFalse(any(call[0] == "PUT" for call in client.calls))


if __name__ == "__main__":
    unittest.main()
