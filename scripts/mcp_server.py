#!/usr/bin/env python3
"""Authenticated Streamable HTTP MCP; no controller mutation tools exist."""
from __future__ import annotations

import argparse
import hmac
import ipaddress
import logging
import os
import re
import socket
from typing import Any

import anyio
import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.responses import JSONResponse

from mcp_readonly import ReadOnlyTools
from unifi_common import load_env

DESCRIPTIONS = {
    'controller_info': 'Read installed UniFi Network application information.',
    'discover_sites': 'Discover sites without choosing an ambiguous default.',
    'networks': 'Read networks, VLAN IDs, subnets and DHCP ranges (legacy/private API).',
    'active_clients': 'Read a bounded page of active connected clients.',
    'client_lookup': 'Find active clients by partial name or exact MAC/IP within a bounded page.',
    'firewall_policies': 'Read official Integration v1 firewall policies; no policy changes.',
    'port_forwards': 'Read configured port forwards; does not test WAN reachability.',
    'ids_ips_events': 'Read legacy IDS/IPS events when GET is supported. Coverage is limited, especially on newer firmware; never infer no threats from empty results.',
    'network_summary': 'Read high-level application and network counts with explicit coverage limitations.',
}


def validate_token(token):
    if not re.fullmatch(r'[A-Za-z0-9_-]{43,256}', token) or len(set(token)) < 16:
        raise ValueError('UNIFI_MCP_TOKEN must be a strong URL-safe token generated with secrets.token_urlsafe(32)')


def bind_address(value):
    if value == 'container' and os.path.isfile('/.dockerenv'):
        value = socket.gethostbyname(socket.gethostname())
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError('UNIFI_MCP_BIND must be a loopback/private IP, or container inside Docker') from None
    private = any(address in subnet for subnet in (
        ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16')) if address.version == subnet.version)
    if not address.is_loopback and not private:
        raise ValueError('MCP binding must be loopback or an RFC1918 interface; wildcard/public bindings are refused')
    return str(address)


class BearerBoundary:
    """Authenticate every HTTP request before parsing MCP, and sanitize SDK output."""
    def __init__(self, app, token, sanitizer):
        self.app, self.token, self.sanitizer = app, token.encode(), sanitizer

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        headers = [v for k, v in scope['headers'] if k.lower() == b'authorization']
        valid = False
        if len(headers) == 1:
            scheme, _, value = headers[0].partition(b' ')
            valid = scheme.lower() == b'bearer' and hmac.compare_digest(value, self.token)
        if not valid:
            return await JSONResponse({'error': 'Unauthorized'}, status_code=401,
                headers={'WWW-Authenticate': 'Bearer', 'Cache-Control': 'no-store'})(scope, receive, send)
        # Stateless JSON responses are buffered to redact even secrets split across chunks.
        start, chunks = None, []
        async def protected_send(message):
            nonlocal start
            if message['type'] == 'http.response.start':
                start = message
            elif message['type'] == 'http.response.body':
                chunks.append(message.get('body', b''))
                if not message.get('more_body', False):
                    body = self.sanitizer.wire(b''.join(chunks))
                    start['headers'] = [(k, v) for k, v in start['headers'] if k.lower() not in (b'content-length', b'cache-control')]
                    start['headers'] += [(b'content-length', str(len(body)).encode()), (b'cache-control', b'no-store')]
                    await send(start)
                    await send({'type': 'http.response.body', 'body': body})
        try:
            await self.app(scope, receive, protected_send)
        except Exception:
            await JSONResponse({'error': 'MCP request failed'}, status_code=500)(scope, receive, send)


def create_app(env=None, client_factory=None):
    env = dict(load_env() if env is None else env)
    validate_token(env.get('UNIFI_MCP_TOKEN', ''))
    facade = ReadOnlyTools(env, client_factory)
    # SDK diagnostics can contain request arguments; emit no SDK payload logs.
    for name in ('mcp', 'mcp.server', 'mcp.server.fastmcp', 'mcp.server.lowlevel.server',
                 'mcp.server.streamable_http', 'mcp.server.streamable_http_manager'):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    hosts = ['127.0.0.1:*', 'localhost:*', '[::1]:*', 'unifi-mcp:*']
    extra_hosts = env.get('UNIFI_MCP_ALLOWED_HOSTS', '')
    for host in filter(None, (x.strip() for x in extra_hosts.split(','))):
        if '*' in host or '/' in host or '@' in host:
            raise ValueError('UNIFI_MCP_ALLOWED_HOSTS entries must be exact host:port values')
        hosts.append(host)
    server = FastMCP('UniFi read-only', stateless_http=True, json_response=True, log_level='CRITICAL',
        max_request_body_size=16384, transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=[]))
    limiter = anyio.CapacityLimiter(4)
    annotations = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)
    def register(name):
        async def read(site: str | None = None, limit: int = 100, offset: int = 0) -> dict[str, Any]:
            return await anyio.to_thread.run_sync(lambda: facade.execute(name, site, limit, offset), limiter=limiter)
        server.tool(name=name, description=DESCRIPTIONS[name], annotations=annotations, structured_output=True)(read)
    for name in DESCRIPTIONS:
        if name != 'client_lookup':
            register(name)
    @server.tool(name='client_lookup', description=DESCRIPTIONS['client_lookup'], annotations=annotations, structured_output=True)
    async def lookup(query: str, site: str | None = None, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        return await anyio.to_thread.run_sync(lambda: facade.execute('client_lookup', site, limit, offset, query), limiter=limiter)
    return BearerBoundary(server.streamable_http_app(), env['UNIFI_MCP_TOKEN'], facade.sanitizer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        env = load_env()
        address = bind_address(env.get('UNIFI_MCP_BIND', '127.0.0.1'))
        app = create_app(env)
        # Validate client configuration without making a request.
        from mcp_readonly import make_client
        make_client(env)
    except ValueError:
        raise SystemExit('Invalid MCP configuration; check token, read-only gate, bind address and controller credentials. Values withheld.') from None
    uvicorn.run(app, host=address, port=8765, access_log=False, log_level='critical', proxy_headers=False)


if __name__ == '__main__':
    main()
