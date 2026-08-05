"""Bind an account key from the command line.

Headless machines have no browser, and /api/tunnel/bind sits behind the admin
session, so the web UI cannot be the only way in. This does the same work
directly against the filesystem: anyone who can run it already owns the config
directory, which is the same trust boundary the web session protects.

    python -m gntl.bind_cli gtnl-... [--port 2026]

or, more usually:

    ./run.sh bind gtnl-... [port]
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

from .main import (
    APP_HTTPS_PORT,
    FRP_SERVER_PORT,
    TUNNEL_BIND_SERVER,
    _configs_dir,
    _detect_local_app_protocol,
    _instance_id_for_owner,
    _load_tunnel_keys,
    _save_tunnel_keys,
    render_frpc_config,
)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
SERVICE_NAME = 'gntl.service'


def _post_json(url: str, payload: dict, timeout: float = 20.0) -> dict:
    body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        url, data=body, headers={'Content-Type': 'application/json'}, method='POST'
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode('utf-8'))
        except Exception:
            return {'success': False, 'error': f'HTTP {e.code}'}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def _service_is_active() -> bool:
    try:
        out = subprocess.run(
            ['systemctl', 'is-active', SERVICE_NAME],
            capture_output=True, text=True, timeout=10,
        )
        return out.stdout.strip() == 'active'
    except Exception:
        return False


def _extract_key(raw: str) -> str:
    """Accept a bare key or the whole 'Link format' line from the keys page."""
    key = (raw or '').strip().strip('"').strip("'")
    if 'token=' in key:
        key = key.split('token=', 1)[1].split('&', 1)[0].strip()
    return key


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog='gntl bind',
        description='Bind this machine to a ginto.ai subdomain using an account key.',
    )
    parser.add_argument('key', help='account key from ginto.ai/account/keys (gtnl-...)')
    parser.add_argument(
        '--port', '-p', type=int, default=APP_HTTPS_PORT,
        help=f'local port to expose (default {APP_HTTPS_PORT})',
    )
    parser.add_argument(
        '--owner', default='admin',
        help='local owner the tunnel is filed under (default admin)',
    )
    parser.add_argument(
        '--no-restart', action='store_true',
        help='write the config but do not (re)start the tunnel',
    )
    args = parser.parse_args(argv)

    key = _extract_key(args.key)
    if not key.startswith('gtnl-'):
        print('error: that does not look like an account key (expected gtnl-...)', file=sys.stderr)
        return 2
    if args.port < 1 or args.port > 65535:
        print('error: --port must be between 1 and 65535', file=sys.stderr)
        return 2

    url = f"{TUNNEL_BIND_SERVER.rstrip('/')}/api/tunnel/bind"
    client = socket.gethostname()

    print(f'-> authorising key with {TUNNEL_BIND_SERVER} ...')
    info = _post_json(url, {'key': key, 'local_port': args.port, 'client': client})
    if not info.get('success'):
        print(f"error: {info.get('error') or 'bind rejected'}", file=sys.stderr)
        print('       Generate a fresh key at '
              f"{TUNNEL_BIND_SERVER}/account/keys if this one was revoked or expired.",
              file=sys.stderr)
        return 1

    subdomain = str(info.get('subdomain') or '')
    server_addr = str(info.get('server_addr') or 'ginto.ai')
    server_port = int(info.get('server_port') or FRP_SERVER_PORT)
    proxy_type = str(info.get('proxy_type') or 'http')
    meta_name = str(info.get('meta_key_name') or 'ginto_key')
    hostname = str(info.get('hostname') or f'{subdomain}.{server_addr}')

    local_is_tls = _detect_local_app_protocol(
        '127.0.0.1', args.port, server_name=hostname
    ) == 'https'

    instance_id = _instance_id_for_owner(args.owner, subdomain, proxy_type)
    cfg_path = os.path.join(_configs_dir(), f'{instance_id}.toml')
    cfg_text = render_frpc_config(
        server_addr=server_addr,
        server_port=server_port,
        auth_token=str(info.get('frp_token') or ''),
        proxy_name=f'{subdomain}-{proxy_type}',
        local_port=args.port,
        subdomain=subdomain,
        protocol=proxy_type,
        local_is_tls=local_is_tls,
        metadatas={meta_name: key},
    )
    with open(cfg_path, 'w', encoding='utf-8') as f:
        f.write(cfg_text)
    os.chmod(cfg_path, 0o600)
    print(f'-> wrote {cfg_path}'
          f"{' (TLS origin, bridged with http2https)' if local_is_tls else ''}")

    keys = _load_tunnel_keys()
    keys[subdomain] = {
        'key': key,
        'subdomain': subdomain,
        'localPort': args.port,
        'instanceId': instance_id,
        'serverAddr': server_addr,
        'serverPort': server_port,
        'frpToken': info.get('frp_token'),
        'expiresAt': info.get('expires_at'),
        'boundAt': int(time.time()),
        'owner': args.owner,
    }
    _save_tunnel_keys(keys)
    print('-> saved the key to configs/tunnel_keys.json (0600)')

    if args.no_restart:
        print('\nConfig written. Start it with:  ./run.sh')
        return 0

    # The manager owns instance state, so let it adopt the new config rather
    # than starting a second frpc behind its back.
    if _service_is_active():
        print(f'-> restarting {SERVICE_NAME} so it picks up the tunnel ...')
        subprocess.run(['systemctl', 'restart', SERVICE_NAME], check=False)
        time.sleep(4)
    else:
        print(f'-> {SERVICE_NAME} is not running')
        print('   Start gntl (./run.sh), or install the boot service:'
              '  ./run.sh install-service')
        print(f'\nBound: https://{hostname}  ->  127.0.0.1:{args.port}')
        return 0

    print('-> confirming the key on the live tunnel ...')
    confirm = _post_json(url, {'key': key, 'local_port': args.port, 'client': client})
    verified = bool(confirm.get('meta_verified'))

    print(f'\nBound: https://{hostname}  ->  127.0.0.1:{args.port}')
    if verified:
        print('Key verified on the live tunnel. The subdomain is authorised.')
    else:
        print('Note: the server could not yet see the key on the live tunnel.')
        print('      Give it a few seconds and re-run this command; if it keeps')
        print('      failing, check the tunnel is up:  tail -f /tmp/frpc-tunnel.log')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
