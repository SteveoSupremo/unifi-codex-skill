import copy
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))

from audit import markdown
from auditlib import analyze_inventory
from auditlib.telemetry import analyze_telemetry
from inventory import collect_inventory
from test_inventory import FakeClient, site


def sample():
    return {
        "collection_started_at": "2026-10-17T23:45:00+00:00",
        "collection_finished_at": "2026-10-17T23:45:02+00:00",
        "status": {"health": [{"subsystem": "wan", "status": "ok"}]},
        "devices": [{"name": "Test AP", "type": "uap",
                     "system-stats": {"cpu": "5.2", "mem": 40},
                     "radio_table_stats": [{"radio": "ng", "channel": 6,
                                            "cu_total": 95, "tx_retries_pct": 25}]}],
    }


class TelemetryTests(unittest.TestCase):
    def test_congestion_and_retry_candidates_preserve_observation_time(self):
        data = sample()
        original = copy.deepcopy(data)
        result = analyze_inventory(data, "wifi")
        self.assertEqual(len(result.findings), 2)
        self.assertTrue(all(f.evidence_type == "reported" and not f.safe_to_automate for f in result.findings))
        self.assertEqual(result.telemetry["collection_finished_at"], data["collection_finished_at"])
        self.assertEqual(result.coverage["Radio utilization/retries"], "collected and analyzed")
        self.assertEqual(data, original)

    def test_cpu_memory_and_subsystem_health(self):
        data = sample()
        data["devices"][0]["system-stats"] = {"cpu": "90", "mem": 98}
        data["status"]["health"][0]["status"] = "warning"
        result = analyze_inventory(data, "health")
        self.assertEqual(len(result.findings), 3)
        self.assertNotIn("Radio utilization/retries", result.coverage)

    def test_empty_status_wrapper_does_not_mean_healthy(self):
        result = analyze_inventory({"status": {"health": None, "sysinfo": None}}, "health")
        self.assertEqual(result.findings[0].evidence_type, "not_available")
        self.assertTrue(all(value == "no usable telemetry" for value in result.coverage.values()))

    def test_invalid_percentages_do_not_become_findings_or_healthy_samples(self):
        for value in (True, False, None, "bad", "NaN", float("inf"), -1, 101, [], {}):
            with self.subTest(value=value):
                data = sample()
                data["devices"][0]["radio_table_stats"][0].update(cu_total=value, tx_retries_pct=value)
                result = analyze_inventory(data, "wifi")
                self.assertEqual(result.telemetry["observations"], [])
                self.assertEqual([f.evidence_type for f in result.findings], ["not_available"])

    def test_zero_is_valid_and_cumulative_retry_counters_are_not_rates(self):
        data = sample()
        data["devices"][0]["radio_table_stats"] = [{"cu_total": 0, "tx_retries": 900000}]
        result = analyze_inventory(data, "wifi")
        self.assertEqual(len(result.telemetry["observations"]), 1)
        self.assertEqual(result.telemetry["observations"][0]["value"], 0)
        self.assertEqual(result.coverage["Radio utilization/retries"], "partially analyzed")
        self.assertTrue(all(f.severity == "informational" for f in result.findings))

    def test_unavailable_dataset_ignores_retained_values_and_partial_remains_partial(self):
        for state in ("unavailable", "partial"):
            with self.subTest(state=state):
                data = sample()
                data["collection_status"] = {"devices": {"status": state}}
                result = analyze_inventory(data, "wifi")
                self.assertNotEqual(result.coverage["Radio utilization/retries"], "collected and analyzed")
                if state == "unavailable":
                    self.assertEqual(result.telemetry["observations"], [])

    def test_malformed_records_and_containers_do_not_abort(self):
        for value in (None, "bad", 5, [None, 5, {}], {}):
            with self.subTest(value=value):
                result = analyze_inventory({"devices": value, "status": value,
                                            "collection_status": value}, "performance")
                self.assertTrue(result.findings)

    def test_history_does_not_establish_current_connection_state(self):
        data = {"legacy_clients": [{"name": "TV", "last_disconnect": 123, "signal": -95}],
                "status": {"health": []}}
        result = analyze_inventory(data, "wifi")
        self.assertFalse(any("TV" in f.title for f in result.findings))
        self.assertEqual(result.telemetry["observations"], [])

    def test_missing_timestamp_is_explicit_and_scope_report_is_relevant(self):
        data = sample()
        del data["collection_started_at"]
        result = analyze_inventory(data, "wifi")
        report = markdown(result)
        self.assertIn("unknown", report)
        self.assertTrue(any("timestamps are unavailable" in item for item in result.unknowns))
        self.assertIn("95.0%", report)
        self.assertNotIn("Effective Segmentation", report)

    def test_inventory_records_utc_collection_window(self):
        result = collect_inventory(FakeClient([site()]))
        start = dt.datetime.fromisoformat(result["collection_started_at"])
        end = dt.datetime.fromisoformat(result["collection_finished_at"])
        self.assertEqual(start.utcoffset(), dt.timedelta(0))
        self.assertLessEqual(start, end)

    def test_all_scope_includes_telemetry(self):
        data = sample()
        data.update(networks=[], port_forwards=[])
        result = analyze_inventory(data, "all")
        self.assertTrue(result.as_dict()["telemetry"]["observations"])
        self.assertTrue(any("channel utilization" in f.title for f in result.findings))
        self.assertIn("Radio utilization/retries", result.coverage)
        self.assertIn(result.telemetry["limitations"][0], result.unknowns)

    def test_offline_cli_emits_telemetry_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.json"
            path.write_text(json.dumps(sample()))
            command = [sys.executable, str(Path(__file__).parents[1] / "scripts/audit.py"),
                       "performance", "--input", str(path)]
            result = subprocess.run(command + ["--json"], capture_output=True, text=True, check=True)
            payload = json.loads(result.stdout)
            self.assertFalse(payload["live_mutation"])
            self.assertEqual(len(payload["telemetry"]["observations"]), 5)
            report = subprocess.run(command, capture_output=True, text=True, check=True).stdout
            self.assertIn("Reported Telemetry", report)
            self.assertNotIn("VPN / Management Access", report)


if __name__ == "__main__":
    unittest.main()
