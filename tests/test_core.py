import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).parents[1]/"scripts"))
from unifi_common import deep_modified, json_diff, load_env, redact, require_write_authorization
from snapshot import create_snapshot
from audit import analyze

class CoreTests(unittest.TestCase):
 def test_env_precedence(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/".env"; p.write_text("UDM_HOST=file-host\nUNIFI_API_KEY=secret\n")
   old=os.environ.get("UDM_HOST"); os.environ["UDM_HOST"]="env-host"
   try:self.assertEqual(load_env(p)["UDM_HOST"],"env-host")
   finally:
    if old is None:os.environ.pop("UDM_HOST",None)
    else:os.environ["UDM_HOST"]=old
 def test_redaction_recursive(self): self.assertEqual(redact({"api_key":"abc","nested":{"password":"x"}}),{"api_key":"<redacted>","nested":{"password":"<redacted>"}})
 def test_full_object_copy(self):
  before={"id":"1","name":"old","untouched":{"x":1}}; after=deep_modified(before,{"name":"new"})
  self.assertEqual(after["untouched"],{"x":1}); self.assertEqual(before["name"],"old"); self.assertIn("+  \"name\": \"new\"",json_diff(before,after))
 def test_read_only_enforcement(self):
  with mock.patch.dict(os.environ,{"UNIFI_ENABLE_WRITES":"disabled"}):
   with self.assertRaises(PermissionError):require_write_authorization(explicit=True,approved=True,level=2,dry_run=False)
   require_write_authorization(explicit=True,approved=True,level=2,dry_run=True)
 def test_snapshot(self):
  with tempfile.TemporaryDirectory() as d:
   folder=create_snapshot("controller","firewall-rule","123",{"name":"x","token":"bad"},"test",base=Path(d))
   self.assertEqual(json.loads(next(folder.glob("firewall-rule*.json")).read_text())["token"],"<redacted>")
 def test_low_level_cli_refuses_raw_write_before_credentials(self):
  commands=[["raw","POST","/unsafe"],["portforward","delete","unsafe-id"],
            ["firewall","delete","unsafe-id"]]
  for command in commands:
   with self.subTest(command=command):
    result=subprocess.run([sys.executable,str(Path(__file__).parents[1]/"scripts"/"udm.py"),*command],capture_output=True,text=True)
    self.assertEqual(result.returncode,2)
    self.assertIn("unguarded low-level writes are disabled",result.stderr)
 def test_audit_classification(self):
  f=analyze({"port_forwards":[{"name":"web","enabled":True,"fwd":"192.0.2.2","dst_port":"443"}]},"exposure")
  self.assertEqual(f[0].severity,"medium"); self.assertFalse(f[0].safe_to_automate)
if __name__=="__main__":unittest.main()
