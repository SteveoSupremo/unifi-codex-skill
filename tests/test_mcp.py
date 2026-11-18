"""MCP tests use synthetic data and deny real socket connections."""
import contextlib
import io
import json
import logging
import os
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from mcp_readonly import ReadOnlyTools, Sanitizer, make_client, NoRedirect
try:
    from starlette.testclient import TestClient
    from mcp_server import create_app, DESCRIPTIONS, bind_address
    HAS_MCP = True
except ImportError:
    HAS_MCP = False

TOKEN = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJK'
SECRET = 'synthetic-controller-api-key'
ENV = {'UNIFI_MCP_TOKEN': TOKEN, 'UNIFI_API_KEY': SECRET, 'UDM_HOST': 'controller.test',
       'UNIFI_ENABLE_WRITES': 'disabled', 'UNIFI_VERIFY_TLS': 'true'}


class FakeClient:
    base = 'https://controller.test'
    def __init__(self):
        self.calls = []
        self.fail = False
        self.multiple = False
        self.total = 2

    def get_optional(self, url, *, unwrap):
        self.calls.append(('GET', url))
        if self.fail:
            raise RuntimeError(SECRET + TOKEN)
        if url.endswith('/info'):
            return {'applicationVersion': '10.test', 'apiKey': SECRET}
        if url.endswith('/sites'):
            sites = [{'id': 'uuid', 'internalReference': 'default', 'name': 'Home', 'token': TOKEN}]
            if self.multiple:
                sites.append({'id': 'other', 'internalReference': 'lab', 'name': 'Lab'})
            return {'data': sites}
        if '/clients?' in url:
            from urllib.parse import parse_qs, urlsplit
            q = parse_qs(urlsplit(url).query)
            offset, limit = int(q['offset'][0]), int(q['limit'][0])
            records = [{'id': str(i), 'name': 'Laptop' if i == 0 else 'Phone', 'macAddress': 'AA:BB:CC:DD:EE:FF' if i == 0 else '00:11:22:33:44:55', 'ipAddress': '192.0.2.10' if i == 0 else '192.0.2.11', 'password': SECRET} for i in range(self.total)]
            return {'data': records[offset:offset + limit], 'totalCount': self.total, 'offset': offset}
        if '/firewall/policies?' in url:
            return {'data': [{'id': 'policy', 'name': 'DNS', 'source': {'zoneId': 'lan', 'psk': 'synthetic-psk'}, 'metadata': {'note': SECRET, 'cookie': 'cookie-value'}}], 'totalCount': 1}
        if '/networkconf' in url:
            return {'data': [{'name': 'LAN', 'vlan': 7, 'ip_subnet': '192.0.2.0/24', 'x_password': SECRET}]}
        if '/portforward' in url:
            return {'data': [{'name': 'HTTPS', 'fwd': '192.0.2.5', 'dst_port': '443', 'secret': SECRET}]}
        if '/stat/ips/event' in url:
            return {'data': [{'signature': 'Synthetic alert', 'severity': 2, 'apiKey': SECRET}]}
        raise AssertionError('Unexpected endpoint')


class ReadOnlyFacadeTests(unittest.TestCase):
    def setUp(self):
        self.deny_network = mock.patch('socket.socket.connect', side_effect=AssertionError('Live network forbidden'))
        self.deny_network.start()
        self.addCleanup(self.deny_network.stop)
        self.fake = FakeClient()
        self.tools = ReadOnlyTools(ENV, lambda: self.fake)

    def test_controller_info(self):
        self.assertEqual(self.tools.execute('controller_info')['data'], [{'applicationVersion': '10.test'}])

    def test_site_discovery(self):
        self.assertEqual(self.tools.execute('discover_sites')['data'][0]['id'], 'uuid')

    def test_network_vlan(self):
        self.assertEqual(self.tools.execute('networks')['data'][0]['vlan'], 7)

    def test_active_clients(self):
        self.assertEqual(self.tools.execute('active_clients')['returned'], 2)

    def test_client_lookup_name_mac_ip(self):
        for query in ('lap', 'aabbccddeeff', 'AA-BB-CC-DD-EE-FF', '192.0.2.10'):
            with self.subTest(query=query):
                self.assertEqual(self.tools.execute('client_lookup', query=query)['returned'], 1)
        self.assertEqual(self.tools.execute('client_lookup', query='192.0.2.1')['returned'], 0)

    def test_firewall_policies_redact_nested_secrets(self):
        result = self.tools.execute('firewall_policies')
        self.assertEqual(result['data'][0]['source']['psk'], '<redacted>')
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn('cookie-value', json.dumps(result))

    def test_port_forwards(self):
        self.assertEqual(self.tools.execute('port_forwards')['data'][0]['dst_port'], '443')

    def test_ids_events_always_report_limited_coverage(self):
        result = self.tools.execute('ids_ips_events')
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['data'][0]['severity'], 2)

    def test_network_summary(self):
        result = self.tools.execute('network_summary')
        self.assertEqual(result['coverage']['active_clients']['returned'], 2)
        self.assertEqual(result['status'], 'partial')
        self.assertFalse(result['live_mutation'])

    def test_pagination_bounded_and_continuable(self):
        self.fake.total = 550
        result = self.tools.execute('active_clients', limit=500)
        self.assertEqual(result['returned'], 500)
        self.assertTrue(result['has_more'])
        self.assertEqual(len(self.fake.calls), 4)  # discovery + 3 bounded pages
        self.assertEqual(self.tools.execute('active_clients', offset=500)['returned'], 50)

    def test_lookup_reports_incomplete_page(self):
        result = self.tools.execute('client_lookup', query='phone', limit=1)
        self.assertEqual(result['returned'], 0)
        self.assertTrue(result['has_more'])
        self.assertEqual(result['scanned'], 1)

    def test_invalid_limits_and_unknown_tool_never_contact_controller(self):
        for args in ({'limit': 0}, {'limit': 501}, {'offset': -1}, {'offset': 100001}):
            self.assertEqual(self.tools.execute('active_clients', **args)['status'], 'unavailable')
        self.assertEqual(self.tools.execute('raw')['status'], 'unavailable')
        self.assertEqual(self.tools.execute('client_lookup', query='')['status'], 'unavailable')
        self.assertEqual(self.fake.calls, [])

    def test_ambiguous_site_requires_selection(self):
        self.fake.multiple = True
        self.assertEqual(self.tools.execute('networks')['status'], 'unavailable')
        self.assertEqual(self.tools.execute('networks', site='Lab')['status'], 'available')
        self.assertIn('/s/lab/', self.fake.calls[-1][1])

    def test_failure_never_leaks_response_or_logs(self):
        self.fake.fail = True
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            for name in ('controller_info', 'discover_sites', 'networks', 'active_clients', 'client_lookup', 'firewall_policies', 'port_forwards', 'ids_ips_events', 'network_summary'):
                result = self.tools.execute(name, query='laptop')
                self.assertIn(result['status'], ('unavailable', 'partial'))
                self.assertNotIn(SECRET, json.dumps(result))
                self.assertNotIn(TOKEN, json.dumps(result))
        self.assertEqual(output.getvalue(), '')

    def test_writes_enabled_refuses_startup(self):
        with self.assertRaises(ValueError):
            ReadOnlyTools(dict(ENV, UNIFI_ENABLE_WRITES='I_UNDERSTAND_THIS_CHANGES_MY_NETWORK'))

    def test_secret_values_redacted_even_in_keys_and_innocent_fields(self):
        value = Sanitizer(ENV).clean({SECRET: {'name': TOKEN, 'private_key': 'hidden'}})
        self.assertNotIn(SECRET, json.dumps(value))
        self.assertNotIn(TOKEN, json.dumps(value))
        self.assertNotIn('hidden', json.dumps(value))

    def test_client_transport_guard_and_timeout(self):
        # Avoid udm's import-time dotenv side effect loading the real local credentials.
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch('pathlib.Path.is_file', return_value=False):
            client = make_client(ENV)
        with mock.patch.object(client.opener, 'open') as opened:
            for method in ('POST', 'PUT', 'PATCH', 'DELETE'):
                with self.assertRaises(PermissionError):
                    client._request(method, client.base + '/proxy/network/unsafe')
            with self.assertRaises(PermissionError):
                client.get_optional('https://elsewhere.test/proxy/network/info')
            opened.assert_not_called()
            opened.return_value.__enter__.return_value.read.return_value = b'{"data":[]}'
            client.get_optional(client.base + '/proxy/network/integration/v1/sites')
            self.assertEqual(opened.call_args.kwargs['timeout'], 15)
            self.assertEqual(opened.call_args.args[0].method, 'GET')
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, None, None, 'https://elsewhere.test'))

    def test_malformed_pages_fail_without_false_empty_success(self):
        with mock.patch.object(self.fake, 'get_optional', return_value={'unexpected': SECRET}):
            for name in ('controller_info', 'discover_sites', 'active_clients'):
                self.assertEqual(self.tools.execute(name)['status'], 'unavailable')

    def test_controller_identifiers_are_encoded_as_path_segments(self):
        from inventory import SelectedSite
        with mock.patch('mcp_readonly.select_site', return_value=SelectedSite('../x?y', '../z?x', 'Test')):
            self.tools.execute('networks')
        self.assertIn('/s/..%2Fz%3Fx/', self.fake.calls[-1][1])

    def test_get_body_is_refused_and_http_errors_are_quiet(self):
        client = make_client(ENV)
        output = io.StringIO()
        with mock.patch.object(client.opener, 'open', side_effect=urllib.error.HTTPError(client.base, 403, SECRET, {}, None)) as opened:
            with self.assertRaises(PermissionError):
                client._request('GET', client.base + '/proxy/network/info', {'data': 1})
            opened.assert_not_called()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), self.assertRaises(Exception):
                client.get_optional(client.base + '/proxy/network/info')
        self.assertEqual(output.getvalue(), '')

    def test_client_tls_honors_configuration(self):
        for setting, expected in (('true', ssl.CERT_REQUIRED), ('false', ssl.CERT_NONE)):
            client = make_client(dict(ENV, UNIFI_VERIFY_TLS=setting))
            handler = next(h for h in client.opener.handlers if isinstance(h, __import__('urllib.request', fromlist=['HTTPSHandler']).HTTPSHandler))
            self.assertEqual(handler._context.verify_mode, expected)



class TokenFileTests(unittest.TestCase):
    def test_generate_private_token_without_overwriting_other_configuration(self):
        from mcp_token import initialize
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env'
            path.write_text('UDM_HOST=example.test\nUNIFI_API_KEY=synthetic\nUNIFI_MCP_TOKEN=\n')
            path.chmod(0o644)
            self.assertTrue(initialize(path))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            content = path.read_text()
            token = content.split('UNIFI_MCP_TOKEN=')[1].strip()
            self.assertGreaterEqual(len(token), 43)
            self.assertIn('UNIFI_API_KEY=synthetic', content)
            self.assertFalse(initialize(path))
            self.assertEqual(path.read_text(), content)

    def test_symlink_refused(self):
        from mcp_token import initialize
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target'
            target.write_text('unchanged')
            path = Path(directory) / '.env'
            path.symlink_to(target)
            with self.assertRaises(OSError):
                initialize(path)
            self.assertEqual(target.read_text(), 'unchanged')


@unittest.skipUnless(HAS_MCP, 'Install requirements-mcp.txt for MCP HTTP tests')
class MCPHTTPTests(unittest.TestCase):
    def setUp(self):
        self.patch = mock.patch('socket.socket.connect', side_effect=AssertionError('Live network forbidden'))
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.fake = FakeClient()
        self.http = self.enterContext(TestClient(create_app(ENV, lambda: self.fake), base_url='http://localhost:8765'))
        self.headers = {'Authorization': 'Bearer ' + TOKEN, 'Accept': 'application/json, text/event-stream'}

    def rpc(self, method, params=None, headers=None):
        return self.http.post('/mcp', headers=self.headers if headers is None else headers,
            json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})

    def test_initialize(self):
        response = self.rpc('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'test', 'version': '1'}})
        self.assertEqual(response.status_code, 200)
        self.assertIn('serverInfo', response.json()['result'])
        self.assertEqual(self.fake.calls, [])

    def test_missing_wrong_malformed_and_duplicate_auth(self):
        for auth in (None, 'Bearer wrong', 'Basic ' + TOKEN, 'Bearer ', 'Bearer ' + TOKEN + ' '):
            headers = {'Accept': 'application/json, text/event-stream'}
            if auth is not None:
                headers['Authorization'] = auth
            response = self.rpc('tools/list', headers=headers)
            self.assertEqual(response.status_code, 401)
            self.assertIn('WWW-Authenticate', response.headers)
        response = self.http.post('/mcp', headers=[('Authorization', 'Bearer ' + TOKEN), ('Authorization', 'Bearer ' + TOKEN)])
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.fake.calls, [])

    def test_get_delete_and_unknown_paths_require_auth(self):
        for method in ('GET', 'DELETE', 'OPTIONS', 'POST'):
            for path in ('/mcp', '/anything'):
                self.assertEqual(self.http.request(method, path).status_code, 401)
        self.assertEqual(self.fake.calls, [])

    def test_lists_exactly_read_only_tools(self):
        tools = self.rpc('tools/list').json()['result']['tools']
        self.assertEqual({t['name'] for t in tools}, set(DESCRIPTIONS))
        for tool in tools:
            self.assertTrue(tool['annotations']['readOnlyHint'])
            self.assertFalse(tool['annotations']['destructiveHint'])

    def test_every_tool_over_streamable_http(self):
        for name in DESCRIPTIONS:
            with self.subTest(name=name):
                response = self.rpc('tools/call', {'name': name, 'arguments': {'query': 'Laptop'} if name == 'client_lookup' else {}})
                self.assertEqual(response.status_code, 200)
                result = response.json()['result']
                self.assertFalse(result.get('isError', False), result)
                self.assertFalse(result['structuredContent']['live_mutation'])
                self.assertNotIn(SECRET, response.text)
                self.assertNotIn(TOKEN, response.text)
        self.assertTrue(all(method == 'GET' for method, _ in self.fake.calls))

    def test_untrusted_host_and_origin_rejected(self):
        for extra in ({'Host': 'evil.example'}, {'Origin': 'https://evil.example'}):
            response = self.rpc('tools/list', headers=dict(self.headers, **extra))
            self.assertIn(response.status_code, (403, 421))
        self.assertEqual(self.fake.calls, [])

    def test_sdk_errors_sanitize_secret_values(self):
        for params in ({'name': TOKEN, 'arguments': {}}, {'name': 'active_clients', 'arguments': {'limit': SECRET}}):
            response = self.rpc('tools/call', params)
            self.assertNotIn(TOKEN, response.text)
            self.assertNotIn(SECRET, response.text)
        self.assertEqual(self.fake.calls, [])

    def test_weak_or_missing_token_refused(self):
        for token in ('', 'short', 'a' * 64, 'replace-me-with-a-strong-token'):
            with self.assertRaises(ValueError):
                create_app(dict(ENV, UNIFI_MCP_TOKEN=token))

    def test_public_and_wildcard_bindings_refused(self):
        for address in ('0.0.0.0', '::', '8.8.8.8', 'example.com', '169.254.169.254'):
            with self.assertRaises(ValueError):
                bind_address(address)
        for address in ('127.0.0.1', '192.168.6.16', '172.19.0.3'):
            self.assertEqual(bind_address(address), address)


if __name__ == '__main__':
    unittest.main()
