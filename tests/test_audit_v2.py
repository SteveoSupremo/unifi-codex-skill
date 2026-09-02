import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from audit import markdown
from auditlib import analyze_inventory


def inventory(forwards=None, firewall_rules=None, include_firewall=True):
    data = {
        "site": {"name": "Synthetic"},
        "networks": [
            {"_id":"default","name":"Default","vlan":1,"ip_subnet":"192.168.1.1/24"},
            {"_id":"iot","name":"IoT","vlan":3,"ip_subnet":"192.168.3.1/24"},
            {"_id":"servers","name":"Servers","vlan":4,"ip_subnet":"192.168.6.1/24"},
            {"_id":"guest","name":"Guest","vlan":99,"ip_subnet":"192.168.99.1/24"},
        ],
        "devices": [], "traffic_rules": [], "port_forwards": forwards or [], "status": {"health": []},
    }
    if include_firewall:
        data["firewall_rules"] = firewall_rules or []
    return data


def forward(name, port, ip="192.168.6.10", **extra):
    value = {"name":name,"enabled":True,"proto":"tcp","dst_port":str(port),"fwd_port":str(port),"fwd":ip}
    value.update(extra)
    return value


class ExposureTests(unittest.TestCase):
    def assessment(self, rule):
        return analyze_inventory(inventory([rule]), "exposure").port_forwards[0]

    def test_direct_proxmox_management_exposure(self):
        a = self.assessment(forward("Virtualization", 8006, src_limiting_enabled=False))
        self.assertEqual(a.exposure_class, "Administrative Interface")
        self.assertEqual(a.severity, "high")
        self.assertEqual(a.action_class, "HARDEN")

    def test_home_assistant_application_exposure(self):
        a = self.assessment(forward("Home Assistant", 8123, src_limiting_enabled=False))
        self.assertEqual(a.destination_role, "Home Assistant")
        self.assertEqual(a.exposure_class, "Application Service")

    def test_n8n_application_exposure(self):
        a = self.assessment(forward("Automation", 5678, src_limiting_enabled=False))
        self.assertIn("n8n", a.likely_service)
        self.assertEqual(a.severity, "medium")

    def test_80_443_pair_is_reverse_proxy_pattern(self):
        result = analyze_inventory(inventory([
            forward("HTTPS",443,"192.168.6.25",src_limiting_enabled=False),
            forward("HTTP Let's Encrypt",80,"192.168.6.25",src_limiting_enabled=False),
        ]), "exposure")
        self.assertTrue(all(a.destination_role == "likely public web gateway" for a in result.port_forwards))
        self.assertTrue(any("same host" in " ".join(a.evidence) for a in result.port_forwards))

    def test_unknown_service(self):
        a = self.assessment(forward("Mystery", 45678))
        self.assertEqual(a.exposure_class, "Unknown")
        self.assertEqual(a.action_class, "UNKNOWN — INVESTIGATE")

    def test_disabled_forward_ignored(self):
        rule = forward("old", 22); rule["enabled"] = False
        self.assertEqual(analyze_inventory(inventory([rule]), "exposure").port_forwards, [])

    def test_restricted_source_scope(self):
        a = self.assessment(forward("SSH",22,src_limiting_enabled=True,src="198.51.100.0/24"))
        self.assertTrue(a.source_restriction.startswith("restricted"))
        self.assertEqual(a.severity, "medium")

    def test_missing_source_scope_is_unknown(self):
        self.assertEqual(self.assessment(forward("app",1234)).source_restriction, "unknown from collected evidence")

    def test_protected_resource_correlation(self):
        a = self.assessment(forward("Home Proxmox",9999,src_limiting_enabled=False))
        self.assertTrue(a.protected_resource)
        self.assertEqual(a.severity, "high")


class FirewallTests(unittest.TestCase):
    def test_broad_firewall_rule(self):
        rule={"name":"wide","enabled":True,"action":"accept","src":"any","dst":"any","protocol":"all"}
        findings=analyze_inventory(inventory(firewall_rules=[rule]),"firewall").findings
        self.assertTrue(any("Any → Any" in f.title for f in findings))

    def test_guest_to_private_allow_candidate(self):
        rule={"name":"Guest access","enabled":True,"action":"allow","src":"Guest","dst":"Servers"}
        findings=analyze_inventory(inventory(firewall_rules=[rule]),"firewall").findings
        self.assertTrue(any("Guest → private" in f.title for f in findings))

    def test_iot_to_server_allow_candidate(self):
        rule={"name":"IoT access","enabled":True,"action":"allow","src":"IoT","dst":"Servers"}
        findings=analyze_inventory(inventory(firewall_rules=[rule]),"firewall").findings
        self.assertTrue(any("IoT → trusted" in f.title for f in findings))

    def test_missing_firewall_dataset(self):
        data=inventory(include_firewall=False); data.pop("traffic_rules")
        finding=analyze_inventory(data,"firewall").findings[0]
        self.assertEqual(finding.evidence_type,"not_available")


class OutputTests(unittest.TestCase):
    def test_coverage_reporting(self):
        result=analyze_inventory(inventory(),"all")
        self.assertEqual(result.coverage["Networks"],"collected and analyzed")
        self.assertEqual(result.coverage["Clients"],"unavailable")
        self.assertIn("## Audit Coverage",markdown(result))

    def test_secret_redaction_and_json_output(self):
        data=inventory([forward("web",443,password="bad")])
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/"inventory.json"; source.write_text(json.dumps(data))
            run=subprocess.run([sys.executable,str(ROOT/"scripts/audit.py"),"exposure","--input",str(source),"--json"],capture_output=True,text=True,check=True)
        parsed=json.loads(run.stdout)
        self.assertFalse(parsed["live_mutation"])
        self.assertNotIn("bad",run.stdout)
        self.assertIn("port_forward_assessments",parsed)


def official_inventory():
    data=inventory()
    for n,external in zip(data["networks"],["net-default","net-iot","net-servers","net-guest"]): n["external_id"]=external
    data["firewall_zones"]=[
        {"id":"z-internal","name":"Internal","networkIds":["net-default"]},
        {"id":"z-iot","name":"IOT Zone","networkIds":["net-iot"]},
        {"id":"z-servers","name":"Servers Zone","networkIds":["net-servers"]},
        {"id":"z-hotspot","name":"Hotspot","networkIds":["net-guest"]},
        {"id":"z-external","name":"External","networkIds":[]},
        {"id":"z-gateway","name":"Gateway","networkIds":[]},
    ]
    data["firewall_policies"]=[]
    data["clients"]=[];data["wlans"]=[];data["wan_interfaces"]=[]
    data["vpn"]={"servers":[{"name":"Remote VPN","type":"WIREGUARD","enabled":True}],"site_to_site":[]}
    data["ids_ips"]=[{"ips_mode":"ips","advanced_filtering_preference":"manual","honeypot_enabled":False}]
    data["upnp_exposure"]=[]
    return data


def official_policy(name,source,destination,action,index=10000,src_filter=None,dst_filter=None,protocol=None,states=None,enabled=True,origin="USER_DEFINED"):
    return {"id":"policy-"+name,"name":name,"enabled":enabled,"index":index,
        "action":{"type":action,"allowReturnTraffic":False},
        "source":{"zoneId":source,"trafficFilter":src_filter},
        "destination":{"zoneId":destination,"trafficFilter":dst_filter},
        "ipProtocolScope":{"ipVersion":"IPV4_AND_IPV6","protocolFilter":protocol},
        "connectionStateFilter":states,"loggingEnabled":False,"metadata":{"origin":origin,"configurable":True}}


class OfficialFirewallSchemaTests(unittest.TestCase):
    def test_real_schema_is_normalized(self):
        data=official_inventory();data["firewall_policies"]=[official_policy("Guest block","z-hotspot","z-servers","BLOCK",2147483647)]
        result=analyze_inventory(data,"firewall");p=result.normalized_firewall_policies[0]
        self.assertEqual(p["source_zone"],"Hotspot");self.assertEqual(p["destination_zone"],"Servers Zone")
        self.assertEqual(p["action"],"BLOCK");self.assertEqual(p["ip_version"],"IPV4_AND_IPV6")

    def test_effective_segmentation_uses_explicit_ordered_defaults(self):
        data=official_inventory();data["firewall_policies"]=[
            official_policy("Guest block","z-hotspot","z-servers","BLOCK",2147483647,origin="SYSTEM_DEFINED"),
            official_policy("IoT block","z-iot","z-servers","BLOCK",2147483647,origin="SYSTEM_DEFINED"),
            official_policy("Trusted allow","z-internal","z-servers","ALLOW",10000),]
        rows=analyze_inventory(data,"firewall").segmentation
        states={r["relationship"]:r["state"] for r in rows}
        self.assertEqual(next(v for k,v in states.items() if k.startswith("Guest") and "Servers" in k),"BLOCKED")
        self.assertEqual(next(v for k,v in states.items() if k.startswith("IoT") and "Servers" in k),"BLOCKED")
        self.assertEqual(next(v for k,v in states.items() if k.startswith("Default") and "Servers" in k),"ALLOWED")
        self.assertTrue(any(v=="UNKNOWN" for v in states.values()))

    def test_scoped_allow_before_block_is_limited(self):
        data=official_inventory();port_filter={"type":"PORT","portFilter":{"type":"SPECIFIC","items":[{"type":"PORT_NUMBER","value":53}],"matchOpposite":False}}
        data["firewall_policies"]=[official_policy("DNS","z-hotspot","z-internal","ALLOW",100, dst_filter=port_filter),official_policy("default block","z-hotspot","z-internal","BLOCK",999)]
        row=next(r for r in analyze_inventory(data,"firewall").segmentation if r["relationship"].startswith("Guest") and "Default" in r["relationship"])
        self.assertEqual(row["state"],"LIMITED")

    def test_broad_server_allow_candidate(self):
        data=official_inventory();data["firewall_policies"]=[official_policy("Connect","z-internal","z-servers","ALLOW")]
        self.assertTrue(any("Broad access into Servers" in f.title for f in analyze_inventory(data,"firewall").firewall_policy_findings))

    def test_port_forward_correlates_exact_official_policy(self):
        data=official_inventory();data["port_forwards"]=[forward("Admin",8006,"192.168.6.10",src_limiting_enabled=False)]
        dst={"type":"IP_ADDRESS","ipAddressFilter":{"type":"SPECIFIC","items":[{"type":"IP_ADDRESS","value":"192.168.6.10"}],"matchOpposite":False},"portFilter":{"type":"SPECIFIC","items":[{"type":"PORT_NUMBER","value":8006}],"matchOpposite":False}}
        data["firewall_policies"]=[official_policy("Allow Port Forward Admin","z-external","z-servers","ALLOW",30000,dst_filter=dst,origin="SYSTEM_DEFINED")]
        correlation=analyze_inventory(data,"all").port_forwards[0].firewall_correlation
        self.assertIn("Associated official",correlation);self.assertIn("source filtering is not visible",correlation)

    def test_posture_sections_and_machine_output(self):
        data=official_inventory();result=analyze_inventory(data,"all");text=markdown(result)
        for heading in ("## Effective Segmentation Summary","## Firewall Policy Findings","## VPN / Management Access","## IDS/IPS Posture","## UPnP / Dynamic Exposure"):
            self.assertIn(heading,text)
        machine=result.as_dict();self.assertEqual(machine["vpn_management_access"]["remote_management_path"],"plausible")
        self.assertEqual(machine["ids_ips_posture"]["mode"],"ips")
        self.assertEqual(machine["upnp_dynamic_exposure"]["status"],"collected, empty")


if __name__ == "__main__": unittest.main()
