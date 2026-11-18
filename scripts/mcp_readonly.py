"""Bounded GET-only facade over the existing UniFi client and site discovery."""
from __future__ import annotations

import json
import re
import ssl
import urllib.request
from urllib.parse import quote, urlsplit

from inventory import APPLICATION_INFO_ENDPOINT, DISCOVERY_ENDPOINT, select_site
from unifi_common import load_env, redact, writes_enabled

SENSITIVE = re.compile(r'key|password|passwd|secret|token|auth|cookie|psk|passphrase|community|credential|^x_', re.I)
FIELDS = {
    'controller_info': 'applicationVersion version name',
    'discover_sites': 'id internalReference name',
    'networks': '_id id name vlan vlan_enabled purpose ip_subnet dhcpd_enabled dhcpd_start dhcpd_stop enabled',
    'active_clients': 'id mac macAddress name hostname ip ipAddress type networkId connection uptime last_seen is_wired signal rx_bytes tx_bytes',
    'firewall_policies': 'id name enabled action source destination ipProtocolScope connectionStateFilter index metadata',
    'port_forwards': '_id name enabled proto dst_port fwd fwd_port src',
    'ids_ips_events': '_id timestamp time src_ip dest_ip src_port dest_port proto signature severity category action',
}


class Sanitizer:
    def __init__(self, env):
        self.secrets = sorted({str(v) for k, v in env.items() if v and SENSITIVE.search(k)}, key=len, reverse=True)

    def text(self, value):
        for secret in self.secrets:
            value = value.replace(secret, '<redacted>')
        return value

    def clean(self, value):
        value = redact(value)
        if isinstance(value, dict):
            return {self.text(str(k)): '<redacted>' if SENSITIVE.search(str(k)) else self.clean(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.clean(v) for v in value]
        if isinstance(value, str):
            return self.text(value)
        return value

    def wire(self, value: bytes) -> bytes:
        # JSON-only Streamable HTTP responses; also covers SDK validation errors.
        for secret in self.secrets:
            for encoded in (secret.encode(), json.dumps(secret)[1:-1].encode()):
                value = value.replace(encoded, b'<redacted>')
        return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_client(env):
    # Import lazily: udm's existing dotenv loader is not run when mocked tests import this module.
    from udm import UDMClient

    class ReadOnlyClient(UDMClient):
        def _request(self, method, url, body=None, **kwargs):
            parsed = urlsplit(url)
            if (method != 'GET' or body is not None or parsed.scheme != 'https'
                    or parsed.netloc != urlsplit(self.base).netloc
                    or not parsed.path.startswith('/proxy/network/')):
                raise PermissionError('MCP controller transport permits same-controller GET only')
            kwargs['fatal'] = False
            return super()._request(method, url, body, **kwargs)

    host = env.get('UDM_HOST', '')
    parsed = urlsplit('https://' + host)
    if not host or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ValueError('UDM_HOST must be a hostname or IP, optionally with a port')
    if not env.get('UNIFI_API_KEY'):
        raise ValueError('UNIFI_API_KEY is required')
    tls = env.get('UNIFI_VERIFY_TLS', 'true').lower()
    if tls not in ('true', 'false', '1', '0', 'yes', 'no'):
        raise ValueError('UNIFI_VERIFY_TLS must be true or false')
    ctx = ssl.create_default_context()
    if tls in ('false', '0', 'no'):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    return ReadOnlyClient(host, env['UNIFI_API_KEY'], timeout=15, opener=opener)


class ReadOnlyTools:
    def __init__(self, env=None, client_factory=None):
        self.env = dict(load_env() if env is None else env)
        if writes_enabled(self.env):
            raise ValueError('Disable UNIFI_ENABLE_WRITES before starting MCP')
        self.sanitizer = Sanitizer(self.env)
        self.client_factory = client_factory or (lambda: make_client(self.env))

    def _get(self, client, path):
        return client.get_optional(client.base + path, unwrap=False)

    def _site(self, client, site):
        selected = select_site(self._get(client, DISCOVERY_ENDPOINT), site or self.env.get('UNIFI_SITE') or None)
        # Controller-controlled identifiers must remain single URL path segments.
        return quote(selected.integration_id, safe=''), quote(selected.internal_reference, safe='')

    def _project(self, name, records):
        keys = FIELDS[name].split()
        return [{k: row[k] for k in keys if k in row} for row in records if isinstance(row, dict)]

    @staticmethod
    def _records(response):
        if isinstance(response, list):
            records = response
        elif isinstance(response, dict) and isinstance(response.get('data'), list):
            if response.get('meta', {}).get('rc', 'ok') != 'ok':
                raise ValueError('Controller rejected query')
            records = response['data']
        else:
            raise ValueError('Malformed collection')
        if any(not isinstance(row, dict) for row in records):
            raise ValueError('Malformed collection item')
        return records

    def _collection(self, client, path, limit, offset, paginated):
        if not paginated:
            records = self._records(self._get(client, path))
            return records[offset:offset + limit], len(records), offset + limit < len(records)
        result = []
        total = None
        cursor = offset
        while len(result) < limit:
            size = min(200, limit - len(result))
            page = self._get(client, f'{path}?offset={cursor}&limit={size}')
            batch = self._records(page)
            if len(batch) > size:
                raise ValueError('Unexpected pagination')
            if isinstance(page, dict) and 'totalCount' in page:
                total = int(page['totalCount'])
            result.extend(batch)
            cursor += len(batch)
            if not batch or len(batch) < size or (total is not None and cursor >= total):
                break
        return result, total, (cursor < total if total is not None else len(result) == limit)

    def execute(self, name, site=None, limit=100, offset=0, query=None):
        """Return explicit coverage; never return exception text or raw controller objects."""
        try:
            if name not in FIELDS and name not in ('client_lookup', 'network_summary'):
                raise ValueError('Unknown tool')
            if not 1 <= limit <= 500 or not 0 <= offset <= 100000:
                raise ValueError('Invalid bounds')
            if site is not None and (not isinstance(site, str) or len(site) > 128):
                raise ValueError('Invalid site')
            if name == 'client_lookup' and (not isinstance(query, str) or not query.strip() or len(query) > 128):
                raise ValueError('Invalid query')
            if name == 'network_summary':
                sections = {key: self.execute(key, site, 500) for key in ('controller_info', 'networks', 'active_clients', 'firewall_policies', 'port_forwards', 'ids_ips_events')}
                return self.sanitizer.clean({'status': 'available' if all(s['status'] == 'available' for s in sections.values()) else 'partial', 'live_mutation': False,
                    'coverage': {k: {field: v[field] for field in ('status', 'returned', 'total', 'has_more', 'note') if field in v} for k, v in sections.items()},
                    'application': sections['controller_info'].get('data', []),
                    'note': 'Counts describe returned API records, not Internet reachability or proof of security. HP ProCurve is outside UniFi control.'})
            client = self.client_factory()
            if name == 'controller_info':
                response = self._get(client, APPLICATION_INFO_ENDPOINT)
                if not isinstance(response, dict) or not any(k in response for k in ('applicationVersion', 'version')):
                    raise ValueError('Malformed application information')
                records, total, more, family = [response], 1, False, 'official/integration-v1'
            elif name == 'discover_sites':
                records, total, more = self._collection(client, DISCOVERY_ENDPOINT, limit, offset, False)
                family = 'official/integration-v1'
            else:
                site_id, internal = self._site(client, site)
                paths = {
                    'networks': (f'/proxy/network/api/s/{internal}/rest/networkconf', False),
                    'active_clients': (f'/proxy/network/integration/v1/sites/{site_id}/clients', True),
                    'client_lookup': (f'/proxy/network/integration/v1/sites/{site_id}/clients', True),
                    'firewall_policies': (f'/proxy/network/integration/v1/sites/{site_id}/firewall/policies', True),
                    'port_forwards': (f'/proxy/network/api/s/{internal}/rest/portforward', False),
                    'ids_ips_events': (f'/proxy/network/api/s/{internal}/stat/ips/event?_limit=500', False),
                }
                path, paginated = paths[name]
                family = 'official/integration-v1' if paginated else 'legacy/private (version-sensitive)'
                records, total, more = self._collection(client, path, limit, offset, paginated)
            scanned = len(records)
            if name == 'client_lookup':
                needle = query.strip().casefold()
                normalized = re.sub('[:-]', '', needle)
                records = [r for r in records if any(needle in str(r.get(k, '')).casefold() for k in ('name', 'hostname'))
                    or any(needle == str(r.get(k, '')).casefold() for k in ('ip', 'ipAddress'))
                    or any(normalized == re.sub('[:-]', '', str(r.get(k, '')).casefold()) for k in ('mac', 'macAddress'))]
            data = self._project('active_clients' if name == 'client_lookup' else name, records)
            result = {'status': 'available', 'live_mutation': False, 'api_family': family, 'data': data,
                      'returned': len(data), 'total': total, 'offset': offset, 'has_more': more}
            if name == 'client_lookup':
                result.update(scanned=scanned, note='Searches only this page of active clients; page with offset/limit to continue. Offline clients are not included.')
            if name == 'ids_ips_events':
                result.update(status='partial', note='Legacy GET only, at most 500 events in the controller-defined window. Empty results do not prove absence of threats; newer firmware may require unsupported POST queries.')
            return self.sanitizer.clean(result)
        except Exception:
            return {'status': 'unavailable', 'live_mutation': False,
                    'note': 'GET failed, response unsupported, site ambiguous, or arguments invalid. No raw errors or credentials are returned.'}
