from fastapi import FastAPI, WebSocket, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import os, time, sqlite3, secrets, hmac, hashlib, base64, re, asyncio
import html
from urllib.parse import parse_qs

from binary_manager import ensure_frpc
from tunnel_manager import FrpcManager
from service_generator import (
    generate_service_bundle,
    install_service_for_current_platform,
    generate_manager_service_bundle,
)

APP_HOST = '127.0.0.1'
APP_PORT = 2026
FRP_SERVER_PORT = 7000
DEFAULT_AUTH_TOKEN = '0868d7a0943085871e506e79c8589bd1d80fbd9852b441165237deea6e16955a'
SESSION_COOKIE_NAME = 'gntl_admin_session'
SESSION_TTL_SECONDS = 60 * 60 * 12
DEFAULT_SESSION_USER = 'admin'


def _configs_dir() -> str:
    path = os.path.join(os.path.dirname(__file__), 'configs')
    os.makedirs(path, exist_ok=True)
    return path


def _auth_db_path() -> str:
    return os.path.join(_configs_dir(), 'webadmin.sqlite3')


def _session_secret_path() -> str:
    return os.path.join(_configs_dir(), '.webadmin_session_secret')


def _db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_auth_db_path())
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS admin_auth (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            n INTEGER NOT NULL,
            r INTEGER NOT NULL,
            p INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )
        '''
    )
    conn.commit()
    return conn


def _password_row():
    conn = _db_connect()
    try:
        cur = conn.execute('SELECT password_hash, salt, n, r, p FROM admin_auth WHERE id = 1')
        return cur.fetchone()
    finally:
        conn.close()


def _has_admin_password() -> bool:
    return _password_row() is not None


def _validate_new_password(password: str):
    if not isinstance(password, str):
        return False, 'password must be a string'
    if len(password) < 12:
        return False, 'password must be at least 12 characters'
    if not re.search(r'[a-z]', password):
        return False, 'password must include a lowercase letter'
    if not re.search(r'[A-Z]', password):
        return False, 'password must include an uppercase letter'
    if not re.search(r'\d', password):
        return False, 'password must include a number'
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, 'password must include a symbol'
    return True, ''


def _normalize_username(username: str) -> str:
    value = (username or '').strip().lower()
    if not re.fullmatch(r'[a-z0-9._-]{3,64}', value):
        raise ValueError('username must be 3-64 chars using a-z, 0-9, dot, dash, underscore')
    return value


def _hash_password(password: str, salt: bytes, n: int = 2**14, r: int = 8, p: int = 1) -> str:
    digest = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=n, r=r, p=p, dklen=64)
    return digest.hex()


def _store_admin_password(password: str):
    valid, err = _validate_new_password(password)
    if not valid:
        raise ValueError(err)

    n, r, p = 2**14, 8, 1
    salt = secrets.token_bytes(16)
    password_hash = _hash_password(password=password, salt=salt, n=n, r=r, p=p)
    now = int(time.time())

    conn = _db_connect()
    try:
        conn.execute(
            '''
            INSERT INTO admin_auth (id, password_hash, salt, n, r, p, created_at, updated_at)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                password_hash = excluded.password_hash,
                salt = excluded.salt,
                n = excluded.n,
                r = excluded.r,
                p = excluded.p,
                updated_at = excluded.updated_at
            ''',
            (password_hash, salt.hex(), n, r, p, now, now),
        )
        conn.commit()
    finally:
        conn.close()


def _verify_admin_password(password: str) -> bool:
    row = _password_row()
    if not row:
        return False
    stored_hash, salt_hex, n, r, p = row
    candidate = _hash_password(password=password, salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p))
    return hmac.compare_digest(stored_hash, candidate)


def _session_secret() -> bytes:
    path = _session_secret_path()
    if os.path.exists(path):
        with open(path, 'rb') as f:
            value = f.read().strip()
        if value:
            return base64.urlsafe_b64decode(value)
    secret = secrets.token_bytes(32)
    with open(path, 'wb') as f:
        f.write(base64.urlsafe_b64encode(secret))
    os.chmod(path, 0o600)
    return secret


def _create_session_cookie_value(username: str) -> str:
    normalized = _normalize_username(username)
    issued = str(int(time.time()))
    nonce = secrets.token_hex(16)
    payload = f'{issued}:{nonce}:{normalized}'
    sig = hmac.new(_session_secret(), payload.encode('utf-8'), hashlib.sha256).hexdigest()
    token = f'{payload}.{sig}'
    return base64.urlsafe_b64encode(token.encode('utf-8')).decode('ascii')


def _session_username(request: Request):
    raw = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw:
        return None
    try:
        token = base64.urlsafe_b64decode(raw.encode('ascii')).decode('utf-8')
        payload, sig = token.rsplit('.', 1)
        expected_sig = hmac.new(_session_secret(), payload.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        issued_str, _nonce, username = payload.split(':', 2)
        issued = int(issued_str)
        if int(time.time()) - issued > SESSION_TTL_SECONDS:
            return None
        return _normalize_username(username)
    except Exception:
        return None


def _is_authenticated(request: Request) -> bool:
    return _session_username(request) is not None


def _request_username(request: Request) -> str:
    return _session_username(request) or DEFAULT_SESSION_USER


def _instance_owner(inst) -> str:
    metadata = inst.metadata or {}
    owner = metadata.get('owner') or DEFAULT_SESSION_USER
    try:
        return _normalize_username(owner)
    except Exception:
        return DEFAULT_SESSION_USER


def _instance_id_for_owner(owner: str, group_id: str, protocol: str) -> str:
    safe_owner = _normalize_username(owner)
    return f'{safe_owner}::{group_id}-{protocol}'


def _auth_redirect_target(request: Request) -> str:
    if _has_admin_password():
        return '/login'
    return '/setup'


def _auth_page(mode: str, message: str = '', username: str = '') -> str:
        is_setup = mode == 'setup'
        title = 'Create Web Admin Password' if is_setup else 'Web Admin Login'
        subtitle = (
                'Access is locked until you create a secure admin password.'
                if is_setup else
                'Authenticate to access the tunnel administration dashboard.'
        )
        primary = 'Save Password' if is_setup else 'Login'
        action = '/setup' if is_setup else '/login'
        confirm_block = (
                '''
                <label for="confirm">Confirm Password</label>
                <input id="confirm" name="confirm" type="password" required minlength="12" autocomplete="new-password" placeholder="Confirm password" />
                '''
                if is_setup else ''
        )
        safe_username = html.escape(username or '')
        policy_hint = (
                '<p class="hint">Use at least 12 characters with uppercase, lowercase, number, and symbol.</p>'
                if is_setup else
                '<p class="hint">Session is protected with secure cookie settings and expires after 12 hours.</p>'
        )
        error_block = f'<div class="alert">{html.escape(message)}</div>' if message else ''

        return f'''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width,initial-scale=1" />
            <title>{title}</title>
            <link rel="icon" type="image/png" href="/static/favicon.png" />
            <style>
                :root{{
                    --bg:#0f1724; --card:#0b1220; --muted:#98a0b3; --accent:#3b82f6; --accent-2:#7c3aed;
                    --text:#e6eef8; --danger:#ef4444; --border:rgba(255,255,255,0.08); --input:#1e293b;
                }}
                @media (prefers-color-scheme: light) {{
                    :root{{
                        --bg:#ffffff; --card:#f8f9fa; --muted:#6c757d; --text:#212529;
                        --border:rgba(0,0,0,0.10); --input:#f0f0f0;
                    }}
                }}
                *{{box-sizing:border-box}}
                html,body{{height:100%;margin:0}}
                body{{
                    background:radial-gradient(1200px 500px at 80% -10%, rgba(124,58,237,0.18), transparent 60%), var(--bg);
                    color:var(--text);
                    font-family:Inter,Segoe UI,Roboto,Arial,sans-serif;
                    display:flex;
                    align-items:center;
                    justify-content:center;
                    padding:18px;
                }}
                .card{{
                    width:min(560px,100%);
                    background:var(--card);
                    border:1px solid var(--border);
                    border-radius:16px;
                    box-shadow:0 20px 48px rgba(2,6,23,0.42);
                    padding:24px;
                }}
                .brand{{display:flex;align-items:center;gap:12px;margin-bottom:10px}}
                .logo{{
                    width:42px;height:42px;border-radius:10px;
                    background:linear-gradient(135deg,var(--accent),var(--accent-2));
                    display:flex;align-items:center;justify-content:center;
                    color:#fff;font-weight:700;
                }}
                h1{{margin:0 0 8px 0;font-size:24px;line-height:1.2}}
                p{{margin:0 0 18px 0;color:var(--muted);line-height:1.45}}
                .alert{{
                    background:rgba(239,68,68,0.12);
                    color:var(--danger);
                    border:1px solid rgba(239,68,68,0.22);
                    padding:10px 12px;
                    border-radius:10px;
                    margin-bottom:14px;
                    font-size:14px;
                }}
                form{{display:flex;flex-direction:column;gap:12px}}
                label{{font-size:13px;color:var(--muted)}}
                input{{
                    width:100%;
                    background:var(--input);
                    color:var(--text);
                    border:1px solid var(--border);
                    border-radius:10px;
                    padding:12px;
                    outline:none;
                }}
                input:focus{{border-color:var(--accent);box-shadow:0 0 0 2px rgba(59,130,246,0.22)}}
                button{{
                    margin-top:4px;
                    border:none;
                    border-radius:12px;
                    padding:12px 16px;
                    font-weight:650;
                    color:#fff;
                    background:linear-gradient(135deg,var(--accent),var(--accent-2));
                    cursor:pointer;
                    transition:transform .14s ease, box-shadow .2s ease;
                    box-shadow:0 10px 20px rgba(59,130,246,0.28);
                }}
                button:hover{{transform:translateY(-1px)}}
                .hint{{margin-top:12px;font-size:13px}}
            </style>
        </head>
        <body>
            <main class="card">
                <div class="brand">
                    <div class="logo">GT</div>
                    <div>
                        <strong>Ginto Tunnel</strong>
                    </div>
                </div>
                <h1>{title}</h1>
                <p>{subtitle}</p>
                {error_block}
                <form method="post" action="{action}">
                    <label for="username">Username</label>
                    <input id="username" name="username" type="text" required minlength="3" maxlength="64" autocomplete="username" value="{safe_username}" placeholder="admin username" />
                    <label for="password">Password</label>
                    <input id="password" name="password" type="password" required minlength="12" autocomplete="{'new-password' if is_setup else 'current-password'}" placeholder="{'Create secure password' if is_setup else 'Enter admin password'}" />
                    {confirm_block}
                    <button type="submit">{primary}</button>
                </form>
                {policy_hint}
            </main>
        </body>
        </html>
        '''


def _q(value):
    return str(value).replace('\\', '\\\\').replace('"', '\\"')


def resolve_tls_options():
    cert_file = os.environ.get('GNTL_TLS_CERT', '').strip()
    key_file = os.environ.get('GNTL_TLS_KEY', '').strip()

    if not cert_file and not key_file:
        return {}, False

    if not cert_file or not key_file:
        raise RuntimeError('TLS requires both GNTL_TLS_CERT and GNTL_TLS_KEY to be set')

    cert_file = os.path.abspath(cert_file)
    key_file = os.path.abspath(key_file)
    if not os.path.exists(cert_file):
        raise RuntimeError(f'TLS certificate file not found: {cert_file}')
    if not os.path.exists(key_file):
        raise RuntimeError(f'TLS key file not found: {key_file}')

    return {
        'ssl_certfile': cert_file,
        'ssl_keyfile': key_file,
    }, True


def render_frpc_config(server_addr: str, server_port: int, auth_token: str, proxy_name: str, local_port: int, subdomain: str, protocol: str = 'http') -> str:
    protocol = (protocol or 'http').lower().strip()
    if protocol not in ('http', 'https'):
        protocol = 'http'
    host_rewrite_line = f"hostHeaderRewrite = \"127.0.0.1\"\n" if protocol == 'http' else ''
    return (
        f"serverAddr = \"{_q(server_addr)}\"\n"
        f"serverPort = {int(server_port)}\n\n"
        f"[auth]\n"
        f"method = \"token\"\n"
        f"token = \"{_q(auth_token)}\"\n\n"
        f"[transport]\n"
        f"poolCount = 3\n\n"
        f"[transport.tls]\n"
        f"enable = true\n"
        f"disableCustomTLSFirstByte = true\n\n"
        f"[log]\n"
        f"to = \"/tmp/frpc-tunnel.log\"\n"
        f"level = \"info\"\n"
        f"maxDays = 3\n\n"
        f"[[proxies]]\n"
        f"name = \"{_q(proxy_name)}\"\n"
        f"type = \"{_q(protocol)}\"\n"
        f"localIP = \"127.0.0.1\"\n"
        f"localPort = {int(local_port)}\n"
        f"subdomain = \"{_q(subdomain)}\"\n"
        f"{host_rewrite_line}"
    )


def build_app():
    # ensure binary (best-effort)
    try:
        binpath = ensure_frpc()
    except Exception as e:
        binpath = None
        print('Warning: could not ensure frpc binary:', e)

    manager = FrpcManager()
    manager.load_from_disk()
    if binpath and os.path.exists(binpath):
        manager.auto_start_enabled_instances(binpath)
    app = FastAPI()

    @app.middleware('http')
    async def auth_middleware(request: Request, call_next):
        public_paths = {
            '/setup',
            '/login',
            '/logout',
            '/api/auth/setup-status',
            '/api/auth/setup',
            '/api/auth/login',
            '/api/auth/logout',
            '/_status',
        }

        path = request.url.path
        if path.startswith('/static/') or path in public_paths:
            return await call_next(request)

        if not _has_admin_password():
            if path.startswith('/api/'):
                return JSONResponse(status_code=403, content={'detail': 'web admin is locked until password setup'})
            return RedirectResponse(url='/setup', status_code=303)

        if not _is_authenticated(request):
            if path.startswith('/api/'):
                return JSONResponse(status_code=401, content={'detail': 'authentication required'})
            return RedirectResponse(url='/login', status_code=303)

        request.state.username = _request_username(request)

        return await call_next(request)

    # mount static files
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    if os.path.isdir(static_dir):
        app.mount('/static', StaticFiles(directory=static_dir), name='static')

    @app.get('/')
    async def index():
        index_file = os.path.join(templates_dir, 'index.html')
        if os.path.exists(index_file):
            return HTMLResponse(open(index_file, 'r').read())
        raise HTTPException(404, 'UI not found')

    @app.get('/setup')
    async def setup_page():
        if _has_admin_password():
            return RedirectResponse(url='/login', status_code=303)
        return HTMLResponse(_auth_page('setup'))

    @app.post('/setup')
    async def setup_submit(req: Request):
        if _has_admin_password():
            return RedirectResponse(url='/login', status_code=303)
        payload = parse_qs((await req.body()).decode('utf-8'))
        username_raw = (payload.get('username', [''])[0] or '').strip()
        password = (payload.get('password', [''])[0] or '').strip()
        confirm = (payload.get('confirm', [''])[0] or '').strip()
        try:
            username = _normalize_username(username_raw)
        except ValueError as e:
            return HTMLResponse(_auth_page('setup', str(e), username_raw), status_code=400)
        if password != confirm:
            return HTMLResponse(_auth_page('setup', 'password confirmation does not match', username_raw), status_code=400)
        valid, err = _validate_new_password(password)
        if not valid:
            return HTMLResponse(_auth_page('setup', err, username_raw), status_code=400)
        _store_admin_password(password)
        response = RedirectResponse(url='/', status_code=303)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=_create_session_cookie_value(username),
            httponly=True,
            secure=True,
            samesite='strict',
            max_age=SESSION_TTL_SECONDS,
            path='/',
        )
        return response

    @app.get('/login')
    async def login_page(request: Request):
        if not _has_admin_password():
            return RedirectResponse(url='/setup', status_code=303)
        if _is_authenticated(request):
            return RedirectResponse(url='/', status_code=303)
        return HTMLResponse(_auth_page('login'))

    @app.post('/login')
    async def login_submit(req: Request):
        if not _has_admin_password():
            return RedirectResponse(url='/setup', status_code=303)
        payload = parse_qs((await req.body()).decode('utf-8'))
        username_raw = (payload.get('username', [''])[0] or '').strip()
        password = (payload.get('password', [''])[0] or '').strip()
        try:
            username = _normalize_username(username_raw)
        except ValueError as e:
            return HTMLResponse(_auth_page('login', str(e), username_raw), status_code=400)
        if not _verify_admin_password(password):
            return HTMLResponse(_auth_page('login', 'invalid password', username_raw), status_code=401)
        response = RedirectResponse(url='/', status_code=303)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=_create_session_cookie_value(username),
            httponly=True,
            secure=True,
            samesite='strict',
            max_age=SESSION_TTL_SECONDS,
            path='/',
        )
        return response

    @app.post('/logout')
    async def logout_submit():
        response = RedirectResponse(url='/login', status_code=303)
        response.delete_cookie(SESSION_COOKIE_NAME, path='/')
        return response

    @app.get('/api/auth/setup-status')
    async def auth_setup_status(request: Request):
        return {
            'requiresSetup': not _has_admin_password(),
            'authenticated': _is_authenticated(request),
            'username': _session_username(request),
        }

    @app.post('/api/auth/setup')
    async def auth_setup(req: Request):
        if _has_admin_password():
            raise HTTPException(409, 'admin password already configured')
        body = await req.json()
        username_raw = (body.get('username') or '').strip()
        password = (body.get('password') or '').strip()
        confirm = (body.get('confirm') or '').strip()
        try:
            username = _normalize_username(username_raw)
        except ValueError as e:
            raise HTTPException(400, str(e))
        if password != confirm:
            raise HTTPException(400, 'password confirmation does not match')
        valid, err = _validate_new_password(password)
        if not valid:
            raise HTTPException(400, err)
        _store_admin_password(password)
        response = JSONResponse({'ok': True})
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=_create_session_cookie_value(username),
            httponly=True,
            secure=True,
            samesite='strict',
            max_age=SESSION_TTL_SECONDS,
            path='/',
        )
        return response

    @app.post('/api/auth/login')
    async def auth_login(req: Request):
        if not _has_admin_password():
            raise HTTPException(403, 'admin password is not configured')
        body = await req.json()
        username_raw = (body.get('username') or '').strip()
        password = (body.get('password') or '').strip()
        try:
            username = _normalize_username(username_raw)
        except ValueError as e:
            raise HTTPException(400, str(e))
        if not _verify_admin_password(password):
            raise HTTPException(401, 'invalid password')
        response = JSONResponse({'ok': True})
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=_create_session_cookie_value(username),
            httponly=True,
            secure=True,
            samesite='strict',
            max_age=SESSION_TTL_SECONDS,
            path='/',
        )
        return response

    @app.post('/api/auth/logout')
    async def auth_logout():
        response = JSONResponse({'ok': True})
        response.delete_cookie(SESSION_COOKIE_NAME, path='/')
        return response

    # REST API
    @app.get('/api/instances')
    async def list_instances(request: Request):
        out = {}
        owner = _request_username(request)
        for id, inst in manager.instances.items():
            if _instance_owner(inst) != owner:
                continue
            pid = inst.process.pid if inst.process and inst.process.poll() is None else None
            uptime = None
            metadata = inst.metadata or {}
            out[id] = {
                'status': inst.status,
                'config': inst.config_path,
                'pid': pid,
                'uptime': uptime,
                'proxyName': metadata.get('proxyName'),
                'subdomain': metadata.get('subdomain'),
                'serverAddr': metadata.get('serverAddr'),
                'serverPort': metadata.get('serverPort'),
                'localPort': metadata.get('localPort'),
                'enabled': bool(metadata.get('enabled', True)),
                'groupId': metadata.get('groupId'),
                'owner': _instance_owner(inst),
                'protocol': metadata.get('protocol'),
                'serviceInstalled': metadata.get('serviceInstalled'),
                'servicePlatform': metadata.get('servicePlatform'),
                'serviceArchitecture': metadata.get('serviceArchitecture')
            }
        return out

    @app.get('/api/autostart/manager')
    async def manager_autostart_info():
        run_script = os.path.join(os.path.dirname(__file__), 'run.sh')
        bundle = generate_manager_service_bundle(run_script, write_files=False)
        return {
            'ok': True,
            'paths': bundle.get('paths'),
            'installCommands': bundle.get('installCommands'),
            'architecture': bundle.get('architecture'),
        }

    @app.post('/api/autostart/manager/install')
    async def manager_autostart_install():
        run_script = os.path.join(os.path.dirname(__file__), 'run.sh')
        try:
            bundle = generate_manager_service_bundle(run_script, write_files=True)
        except Exception as e:
            return {
                'ok': False,
                'result': {
                    'attempted': False,
                    'installed': False,
                    'platform': None,
                    'error': f'could not prepare service bundle: {e}',
                },
                'paths': {},
                'installCommands': {},
            }
        result = install_service_for_current_platform(bundle)
        return {
            'ok': bool(result.get('installed')),
            'result': result,
            'paths': bundle.get('paths'),
            'installCommands': bundle.get('installCommands'),
        }

    @app.post('/api/instances')
    async def create_instance(req: Request):
        body = await req.json()
        owner = _request_username(req)
        group_id = body.get('id')
        proxy_name = body.get('proxyName', 'proxy')
        subdomain = body.get('subdomain', 'tunnel')
        server_addr = body.get('serverAddr', 'ginto.ai')
        server_port = FRP_SERVER_PORT
        local_port = body.get('localPort') or body.get('serverPort') or 80
        if not group_id:
            raise HTTPException(400, 'id required')

        pair_ids = [
            _instance_id_for_owner(owner, group_id, 'http'),
            _instance_id_for_owner(owner, group_id, 'https'),
        ]
        for pair_id in pair_ids:
            if pair_id in manager.instances:
                raise HTTPException(409, f'instance already exists: {pair_id}')

        os.makedirs('configs', exist_ok=True)
        frpc_path = os.path.abspath(binpath or os.path.join('bin', 'frpc'))
        created = []

        for protocol in ('http', 'https'):
            instance_id = _instance_id_for_owner(owner, group_id, protocol)
            protocol_proxy_name = f"{proxy_name}-{protocol}"
            cfg_text = render_frpc_config(
                server_addr=server_addr,
                server_port=int(server_port),
                auth_token=DEFAULT_AUTH_TOKEN,
                proxy_name=protocol_proxy_name,
                local_port=int(local_port),
                subdomain=subdomain,
                protocol=protocol,
            )
            cfg_path = os.path.join('configs', f"{instance_id}.toml")
            with open(cfg_path, 'w', encoding='utf-8') as f:
                f.write(cfg_text)

            service_bundle = {'paths': {}, 'installCommands': {}, 'architecture': None}
            install_result = {
                'attempted': False,
                'installed': False,
                'platform': None,
                'error': 'per-instance service install disabled; manager service controls autostart',
            }
            try:
                service_bundle = generate_service_bundle(instance_id, frpc_path, cfg_path)
            except Exception as e:
                install_result = {
                    'attempted': False,
                    'installed': False,
                    'platform': None,
                    'error': f'service setup skipped: {e}',
                }

            manager.create_instance(instance_id, cfg_path, metadata={
                'proxyName': protocol_proxy_name,
                'subdomain': subdomain,
                'serverAddr': server_addr,
                'serverPort': int(server_port),
                'localPort': int(local_port),
                'groupId': group_id,
                'owner': owner,
                'protocol': protocol,
                'serviceInstalled': bool(install_result.get('installed')),
                'servicePlatform': install_result.get('platform'),
                'serviceArchitecture': service_bundle.get('architecture'),
                'servicePaths': service_bundle.get('paths'),
                'serviceInstallCommands': service_bundle.get('installCommands'),
                'serviceInstallResult': install_result
            })
            created.append({
                'id': instance_id,
                'groupId': group_id,
                'owner': owner,
                'protocol': protocol,
                'configPath': cfg_path,
            })

        return {
            'ok': True,
            'groupId': group_id,
            'created': created,
        }

    @app.post('/api/instances/{id}/start')
    async def start_instance(id: str, request: Request):
        path = binpath or os.path.join('bin','frpc')
        if not os.path.exists(path):
            raise HTTPException(500, 'frpc binary not found')
        inst = manager.instances.get(id)
        if not inst:
            raise HTTPException(404, 'not found')
        if _instance_owner(inst) != _request_username(request):
            raise HTTPException(403, 'forbidden')
        ok = manager.start_instance(id, path)
        return {'ok': bool(ok)}

    @app.post('/api/instances/{id}/stop')
    async def stop_instance(id: str, request: Request):
        inst = manager.instances.get(id)
        if not inst:
            raise HTTPException(404, 'not found')
        if _instance_owner(inst) != _request_username(request):
            raise HTTPException(403, 'forbidden')
        ok = manager.stop_instance(id)
        return {'ok': bool(ok)}

    @app.post('/api/instances/{id}/restart')
    async def restart_instance(id: str, request: Request):
        path = binpath or os.path.join('bin','frpc')
        if not os.path.exists(path):
            raise HTTPException(500, 'frpc binary not found')
        inst = manager.instances.get(id)
        if not inst:
            raise HTTPException(404, 'not found')
        if _instance_owner(inst) != _request_username(request):
            raise HTTPException(403, 'forbidden')
        inst.enabled = True
        inst.metadata['enabled'] = True
        manager._save_state()
        inst.restart(path)
        return {'ok': True}

    @app.delete('/api/instances/{id}')
    async def delete_instance(id: str, request: Request):
        inst = manager.instances.get(id)
        if not inst:
            raise HTTPException(404, 'not found')
        if _instance_owner(inst) != _request_username(request):
            raise HTTPException(403, 'forbidden')
        ok = manager.delete_instance(id)
        return {'ok': bool(ok)}

    @app.get('/api/instances/{id}/logs')
    async def tail_logs(id: str, request: Request, lines: int = 200):
        inst = manager.instances.get(id)
        if not inst:
            raise HTTPException(404, 'not found')
        if _instance_owner(inst) != _request_username(request):
            raise HTTPException(403, 'forbidden')
        return {'lines': inst.tail(lines)}

    # WebSocket for live logs
    @app.websocket('/ws/logs/{id}')
    async def ws_logs(ws: WebSocket, id: str):
        await ws.accept()
        inst = manager.instances.get(id)
        if not inst:
            await ws.send_text('[no such instance]')
            await ws.close()
            return
        cookie_header = ws.headers.get('cookie', '') or ''
        cookie_parts = [part.strip() for part in cookie_header.split(';') if '=' in part]
        cookie_map = {}
        for part in cookie_parts:
            key, value = part.split('=', 1)
            cookie_map[key.strip()] = value.strip()
        session_value = cookie_map.get(SESSION_COOKIE_NAME)
        if not session_value:
            await ws.send_text('[authentication required]')
            await ws.close()
            return
        mock_request = type('Req', (), {'cookies': {SESSION_COOKIE_NAME: session_value}})()
        owner = _session_username(mock_request)
        if not owner:
            await ws.send_text('[authentication required]')
            await ws.close()
            return
        if _instance_owner(inst) != owner:
            await ws.send_text('[forbidden]')
            await ws.close()
            return
        last_sent = 0
        try:
            while True:
                lines = inst.tail(1000)
                new = lines[last_sent:]
                for l in new:
                    await ws.send_text(l)
                last_sent = len(lines)
                await asyncio.sleep(0.5)
        except Exception:
            try:
                await ws.close()
            except Exception:
                pass

    @app.get('/_status')
    def status():
        return {'ok': True}

    return app


if __name__ == '__main__':
    import asyncio
    app = build_app()
    tls_options, tls_enabled = resolve_tls_options()
    if tls_enabled:
        print(f'TLS enabled for web admin on https://{APP_HOST}:{APP_PORT}')
    else:
        print(f'TLS disabled for web admin on http://{APP_HOST}:{APP_PORT}')
    uvicorn.run(app, host=APP_HOST, port=APP_PORT, **tls_options)
