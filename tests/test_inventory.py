import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))

from inventory import SiteDiscoveryError, build_plan, collect_inventory, select_site


class FakeClient:
    def __init__(self, sites):
        self.sites = sites
        self.site = "must-be-replaced"
        self.calls = []

    def _integration(self, path):
        return f"integration:{path}"

    def get(self, url):
        self.calls.append(("GET", url, self.site))
        return self.sites

    def _read(self, name):
        self.calls.append(("GET", name, self.site))
        return []

    def status(self): return self._read("status")
    def networks(self): return self._read("networks")
    def devices(self): return self._read("devices")
    def firewall_rules(self): return self._read("firewall_rules")
    def traffic_rules(self): return self._read("traffic_rules")
    def portforward_rules(self): return self._read("port_forwards")


def site(site_id="uuid-1", internal="default", name="Default"):
    return {"id": site_id, "internalReference": internal, "name": name}


class InventorySiteTests(unittest.TestCase):
    def test_one_discovered_site_is_selected_after_discovery(self):
        client = FakeClient({"data": [site()]})
        result = collect_inventory(client)
        self.assertEqual(result["site"]["internalReference"], "default")
        self.assertEqual(client.calls[0][0:2], ("GET", "integration:sites"))
        self.assertTrue(all(call[0] == "GET" for call in client.calls))

    def test_non_default_site_scopes_all_subsequent_reads(self):
        client = FakeClient([site("uuid-lab", "homelab", "HomeLab")])
        collect_inventory(client)
        self.assertTrue(all(call[2] == "homelab" for call in client.calls[1:]))

    def test_multiple_sites_without_override_are_ambiguous(self):
        sites = [site(), site("uuid-2", "lab", "Lab")]
        with self.assertRaises(SiteDiscoveryError) as raised:
            collect_inventory(FakeClient(sites))
        self.assertEqual(len(raised.exception.available_sites), 2)

    def test_explicit_override_matches_name_and_uses_internal_reference(self):
        sites = [site(), site("uuid-2", "lab-internal", "Lab")]
        client = FakeClient(sites)
        selected = select_site(sites, "Lab")
        collect_inventory(client, "Lab")
        self.assertEqual(selected.internal_reference, "lab-internal")
        self.assertTrue(all(call[2] == "lab-internal" for call in client.calls[1:]))

    def test_empty_or_malformed_site_response_stops_collection(self):
        for response in ([], {}, {"data": None}, {"unexpected": []}):
            with self.subTest(response=response):
                with self.assertRaises(SiteDiscoveryError):
                    select_site(response)

    def test_plan_is_two_stage_and_does_not_assume_default(self):
        plan = build_plan()
        self.assertEqual(plan["stages"][0]["requests"][0]["method"], "GET")
        self.assertEqual(plan["stages"][0]["requests"][0]["endpoint"], "/proxy/network/integration/v1/sites")
        self.assertTrue(
            all("<discovered-site>" in request["endpoint"] for request in plan["stages"][1]["requests"])
        )
        self.assertTrue(
            all(request["method"] == "GET" for stage in plan["stages"] for request in stage["requests"])
        )


if __name__ == "__main__":
    unittest.main()
