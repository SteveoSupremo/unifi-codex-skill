#!/usr/bin/env python3
"""Create a local MCP token without displaying it or replacing an existing token."""
import os
from pathlib import Path
import secrets
import stat


def initialize(path=None):
    path = path or Path(__file__).resolve().parent.parent / '.env'
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'r+') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Expected a regular .env file')
        os.fchmod(stream.fileno(), 0o600)
        lines = stream.read().splitlines()
        found = False
        for i, line in enumerate(lines):
            key, sep, value = line.partition('=')
            if sep and key.strip() == 'UNIFI_MCP_TOKEN':
                if value.strip().strip('\"\''):
                    return False
                lines[i] = 'UNIFI_MCP_TOKEN=' + secrets.token_urlsafe(32)
                found = True
                break
        if not found:
            lines.append('UNIFI_MCP_TOKEN=' + secrets.token_urlsafe(32))
        stream.seek(0)
        stream.write('\n'.join(lines) + '\n')
        stream.truncate()
        return True


if __name__ == '__main__':
    try:
        changed = initialize()
    except (OSError, ValueError):
        raise SystemExit('Unable to initialize MCP token; check .env file ownership and type.') from None
    print('MCP token generated privately in .env (0600).' if changed else 'Existing MCP token preserved; .env permissions set to 0600.')
