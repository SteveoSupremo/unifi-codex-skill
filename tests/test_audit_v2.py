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
        self.assertEqual(result.coverage["Networks"],"available")
        self.assertEqual(result.coverage["Clients"],"unavailable/not collected")
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


if __name__ == "__main__": unittest.main()
