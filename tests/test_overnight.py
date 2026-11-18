import copy
from datetime import datetime
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from overnight import desired_active, plan
from mutationlib import _policy_semantic_matches


class OvernightTests(unittest.TestCase):
    def test_local_boundaries_and_dst(self):
        for instant, expected in {
            "2026-07-01T23:59+00:00": False, "2026-07-02T00:00+00:00": True,
            "2026-11-18T15:59+00:00": True, "2026-11-18T16:00+00:00": False,
            "2026-11-01T05:30+00:00": True, "2026-11-01T06:30+00:00": True,
            "2026-03-08T07:01+00:00": True,
        }.items():
            with self.subTest(instant=instant):
                self.assertEqual(desired_active(datetime.fromisoformat(instant)), expected)

    def test_two_zones_and_ambiguous_membership(self):
        first, second = "02:00:00:00:00:01", "02:00:00:00:00:02"
        data = dict(status={}, clients=[], active_stations=[], firewall_policies=[],
                    collection_finished_at="2026-11-18T02:00+00:00",
                    wan_interfaces=[dict(id="wan")],
                    networks=[dict(_id="1", external_id="a"), dict(_id="2", external_id="b")],
                    firewall_zones=[dict(id="1", name="Internal", networkIds=["a"]),
                                    dict(id="2", name="IOT", networkIds=["b"]),
                                    dict(id="3", name="External", networkIds=["wan"])],
                    legacy_clients=[dict(mac=first, last_connection_network_id="1"),
                                    dict(mac=second, last_connection_network_id="2")])
        original = copy.deepcopy(data)
        result = plan(data, {}, [first, second])
        self.assertEqual(result, plan(data, {}, [second, first]))
        self.assertEqual(data, original)
        rules = result["candidate_zone_policies"]
        self.assertEqual([(r["source"]["zoneId"], r["source"]["trafficFilter"]["macAddressFilter"]["macAddresses"])
                          for r in rules], [("1", [first]), ("2", [second])])
        for key in ["schedule", "source"]:
            changed = copy.deepcopy(rules[0])
            if key == "schedule":
                changed.pop(key)
            else:
                changed[key].pop("trafficFilter")
            self.assertFalse(_policy_semantic_matches(rules[0], changed))
        data["legacy_clients"].append(copy.deepcopy(data["legacy_clients"][0]))
        result = plan(data, {}, [first, second])
        self.assertFalse(result["approval_available"])
        self.assertEqual(len(result["candidate_zone_policies"]), 1)
        self.assertTrue(any(first in reason for reason in result["blockers"]))
