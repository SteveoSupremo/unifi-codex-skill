import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))

from inventory import (
    APPLICATION_INFO_ENDPOINT, DISCOVERY_ENDPOINT, SITE_READS,
    SiteDiscoveryError, build_plan, collect_inventory, select_site,
)


class OptionalReadError(RuntimeError):
    def __init__(self, status=404):
        self.status = status


class FakeClient:
    base = ""

    def __init__(self, sites, unavailable=()):
        self.sites = sites
        self.site = "must-be-replaced"
        self.calls = []
        self.unavailable = set(unavailable)

    def get(self, url):
        self.calls.append(("GET", url, self.site))
        if url == DISCOVERY_ENDPOINT:
            return self.sites
        raise AssertionError(f"unexpected mandatory GET {url}")

    def get_optional(self, url, *, unwrap=True):
        self.calls.append(("GET", url, self.site))
        if any(marker in url for marker in self.unavailable):
            raise OptionalReadError()
        if url == APPLICATION_INFO_ENDPOINT:
            return {"applicationVersion":"10.5.67"}
        if "offset=" in url:
            return {"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"synthetic"}]}
        return [{"id":"synthetic"}]


def site(site_id="uuid-1", internal="default", name="Default"):
    return {"id":site_id,"internalReference":internal,"name":name}


class InventorySiteTests(unittest.TestCase):
    def test_one_discovered_site_is_selected_after_version_discovery(self):
        client=FakeClient({"data":[site()]})
        result=collect_inventory(client)
        self.assertEqual(result["site"]["internalReference"],"default")
        self.assertEqual(client.calls[0][0:2],("GET",APPLICATION_INFO_ENDPOINT))
        self.assertEqual(client.calls[1][0:2],("GET",DISCOVERY_ENDPOINT))
        self.assertFalse(result["live_mutation"])
        self.assertTrue(all(call[0]=="GET" for call in client.calls))

    def test_non_default_site_scopes_legacy_and_official_reads(self):
        client=FakeClient([site("uuid-lab","homelab","HomeLab")])
        collect_inventory(client)
        endpoints=[call[1] for call in client.calls[2:]]
        self.assertTrue(any("/sites/uuid-lab/clients" in endpoint for endpoint in endpoints))
        self.assertTrue(any("/s/homelab/stat/health" in endpoint for endpoint in endpoints))

    def test_multiple_sites_without_override_are_ambiguous(self):
        with self.assertRaises(SiteDiscoveryError):
            collect_inventory(FakeClient([site(),site("uuid-2","lab","Lab")]))

    def test_explicit_override_matches_name(self):
        sites=[site(),site("uuid-2","lab-internal","Lab")]
        self.assertEqual(select_site(sites,"Lab").internal_reference,"lab-internal")
        self.assertEqual(collect_inventory(FakeClient(sites),"Lab")["site"]["id"],"uuid-2")

    def test_empty_or_malformed_site_response_stops_collection(self):
        for response in ([],{}, {"data":None},{"unexpected":[]}):
            with self.subTest(response=response), self.assertRaises(SiteDiscoveryError):
                select_site(response)

    def test_plan_is_complete_get_only_and_separates_site_identifiers(self):
        plan=build_plan()
        requests=[request for stage in plan["stages"] for request in stage["requests"]]
        self.assertFalse(plan["live_mutation"])
        self.assertTrue(all(request["method"]=="GET" for request in requests))
        self.assertEqual(requests[0]["endpoint"],APPLICATION_INFO_ENDPOINT)
        self.assertEqual(requests[1]["endpoint"],DISCOVERY_ENDPOINT)
        self.assertEqual(len(requests),2+len(SITE_READS))
        official=[r for r in requests if r["api_family"]=="official/integration-v1"]
        for family in ("clients","firewall_zones","firewall_policies","wlans","wan_interfaces","vpn_servers","vpn_site_to_site"):
            self.assertTrue(any(r.get("dataset")==family for r in official),family)

    def test_every_expanded_endpoint_family_is_collected(self):
        result=collect_inventory(FakeClient([site()]))
        for dataset in ("clients","firewall_zones","firewall_policies","wlans","wan_interfaces","upnp_exposure","ids_ips"):
            self.assertEqual(result["collection_status"][dataset]["status"],"available",dataset)
            self.assertIsInstance(result[dataset],list)
        self.assertIsInstance(result["vpn"]["servers"],list)
        self.assertIsInstance(result["vpn"]["site_to_site"],list)

    def test_unsupported_endpoint_is_unavailable_and_collection_continues(self):
        client=FakeClient([site()],unavailable={"/firewall/zones","/stat/portforward","/rest/setting/ips"})
        result=collect_inventory(client)
        for dataset in ("firewall_zones","upnp_exposure","ids_ips"):
            self.assertIsNone(result[dataset])
            self.assertEqual(result["collection_status"][dataset]["status"],"unavailable")
        self.assertEqual(result["collection_status"]["clients"]["status"],"available")

    def test_official_pagination_fetches_all_pages(self):
        class PagingClient(FakeClient):
            def get_optional(self,url,*,unwrap=True):
                self.calls.append(("GET",url,self.site))
                if url==APPLICATION_INFO_ENDPOINT:return {"applicationVersion":"10.5.67"}
                if "/clients" in url:
                    offset=200 if "offset=200" in url else 0
                    return {"offset":offset,"limit":200,"count":1,"totalCount":201,"data":[{"offset":offset}]}
                if "offset=" in url:return {"offset":0,"limit":200,"count":0,"totalCount":0,"data":[]}
                return []
        client=PagingClient([site()])
        result=collect_inventory(client)
        self.assertEqual(len(result["clients"]),2)
        self.assertTrue(any("/clients" in call[1] and "offset=200" in call[1] for call in client.calls))


if __name__=="__main__": unittest.main()
