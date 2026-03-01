from fastapi import FastAPI, WebSocket, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import os, time, sqlite3, secrets, hmac, hashlib, base64, re, asyncio
import html
import subprocess
import json
import pty
import select
import fcntl
import termios
import struct
from urllib.parse import parse_qs

from binary_manager import ensure_frpc
from tunnel_manager import FrpcManager
from service_generator import (
    generate_service_bundle,
    install_service_for_current_platform,
    generate_manager_service_bundle,
)

APP_HOST = '127.0.0.1'
BASE_DIR = os.path.dirname(__file__)


def _env_int(name: str, default: int) -> int:
    raw = str(os.environ.get(name, '') or '').strip()
    if raw == '':
        return int(default)
    try:
        value = int(raw)
    except Exception:
        return int(default)
    if value < 1 or value > 65535:
        return int(default)
    return value


APP_HTTPS_PORT = _env_int('GNTL_HTTPS_PORT', 2026)
APP_HTTP_PORT = _env_int('GNTL_HTTP_PORT', 2027)
FRP_SERVER_PORT = 7000
DEFAULT_AUTH_TOKEN = '0868d7a0943085871e506e79c8589bd1d80fbd9852b441165237deea6e16955a'
SESSION_COOKIE_NAME = 'gntl_admin_session'
SESSION_TTL_SECONDS = 60 * 60 * 12
DEFAULT_SESSION_USER = 'admin'
TERMINAL_COMMAND_TIMEOUT_SECONDS = 20
TERMINAL_MAX_OUTPUT_CHARS = 120000


def _configs_dir() -> str:
    path = os.path.join(BASE_DIR, 'configs')
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


def _session_username_from_cookie_header(cookie_header: str):
    cookie_parts = [part.strip() for part in (cookie_header or '').split(';') if '=' in part]
    cookie_map = {}
    for part in cookie_parts:
        key, value = part.split('=', 1)
        cookie_map[key.strip()] = value.strip()
    session_value = cookie_map.get(SESSION_COOKIE_NAME)
    if not session_value:
        return None
    mock_request = type('Req', (), {'cookies': {SESSION_COOKIE_NAME: session_value}})()
    return _session_username(mock_request)


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
    title = 'Create Web Admin Password' if is_setup else 'Dashboard Login'
    subtitle = (
        'Access is locked until you create a secure admin password.'
        if is_setup else
        'Authenticate to access the tunnel administration dashboard.'
    )
    primary = 'Save Password' if is_setup else 'Login'
    action = '/setup' if is_setup else '/login'
    safe_username = html.escape(username or '')
    policy_hint = (
        '<p class="hint">Use at least 12 characters with uppercase, lowercase, number, and symbol.</p>'
        if is_setup else
        '<p class="hint">Session is protected with secure cookie settings and expires after 12 hours.</p>'
    )
    error_block = f'<div class="alert">{html.escape(message)}</div>' if message else ''
    repo_block = '''
                <section class="repo-cta">
                    <strong>Support this project</strong>
                    <p><a href="https://github.com/oliverbob/gntl" target="_blank" rel="noopener noreferrer">1) Star us on GitHub</a></p>
                    <p><a href="https://github.com/oliverbob/gntl" target="_blank" rel="noopener noreferrer">2) Clone the Repo</a></p>
                    <div class="code-wrap">
                        <pre class="clone-line"><code id="repoCloneCmd">git clone https://github.com/oliverbob/gntl</code></pre>
                        <button class="copy-btn" type="button" data-copy-target="repoCloneCmd">Copy</button>
                    </div>
                </section>
    '''
    tutorial_block = '''
                <section class="tutorial-cta">
                    <strong>Cross-Platform Tutorial</strong>
                    <p>Need setup guidance for your device? Open the guided tutorial.</p>
                    <a href="/tutorial">Open Tutorial</a>
                </section>
    '''
    termux_block = (
        '''
                <section id="termuxCta" class="termux-cta">
                    <strong>Use Ginto Serverless on Android</strong>
                    <p id="termuxDetectMeta">Detecting Android version and matching Termux package...</p>
                    <div class="termux-links">
                        <a id="termuxAutoLink" href="https://github.com/termux/termux-app/releases/latest" target="_blank" rel="noopener noreferrer">Download</a>
                    </div>
                </section>
        '''
    )

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
                .auth-shell{{width:min(560px,100%);display:flex;flex-direction:column;gap:0;align-items:stretch}}
                .card{{
                    width:100%;
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
                .auth-fields{{
                    width:min(300px,100%);
                    border:1px solid var(--border);
                    border-radius:12px;
                    margin:0 auto;
                    padding:12px;
                    min-inline-size:0;
                    display:flex;
                    flex-direction:column;
                    gap:12px;
                }}
                .auth-fields input{{
                    width:100%;
                    background:var(--input);
                    color:var(--text);
                    border:1px solid var(--border);
                    border-radius:10px;
                    padding:12px;
                    outline:none;
                }}
                .auth-fields input:focus{{border-color:var(--border);box-shadow:none;outline:none}}
                .password-wrap{{position:relative}}
                .password-wrap input{{padding-right:46px}}
                .password-toggle{{
                    position:absolute;
                    right:8px;
                    top:50%;
                    transform:translateY(-50%);
                    width:auto;
                    height:auto;
                    border-radius:0;
                    border:none;
                    background:transparent;
                    color:var(--text);
                    cursor:pointer;
                    padding:2px;
                    margin:0;
                    box-shadow:none;
                }}
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
                    width:100%;
                    align-self:stretch;
                }}
                button:hover{{transform:translateY(-1px)}}
                .password-toggle:hover,
                .password-toggle:active{{transform:translateY(-50%)}}
                .hint{{margin-top:12px;font-size:13px}}
                .realm-wrap{{
                    width:100%;
                    display:flex;
                    flex-wrap:nowrap;
                    gap:6px;
                    align-items:center;
                    justify-content:flex-start;
                    margin:4px 0 10px 0;
                }}
                .realm-tab{{
                    border:1px solid var(--border);
                    background:transparent;
                    color:var(--text);
                    border-radius:10px;
                    padding:8px 8px;
                    font-size:12px;
                    font-weight:650;
                    cursor:pointer;
                    box-shadow:none;
                    margin-top:0;
                    width:auto;
                    flex:0 0 auto;
                    margin-right:0;
                    margin-bottom:0;
                }}
                @media(max-width:720px){{
                    .realm-wrap{{flex-wrap:wrap;gap:8px}}
                }}
                .realm-tab.active{{
                    background:linear-gradient(135deg,var(--accent),var(--accent-2));
                    color:#fff;
                    border-color:transparent;
                }}
                .realm-info{{
                    border:1px solid var(--border);
                    border-radius:10px;
                    background:rgba(59,130,246,0.08);
                    color:var(--text);
                    padding:10px 12px;
                    font-size:13px;
                    line-height:1.4;
                    margin-bottom:10px;
                }}
                .termux-cta{{
                    border:1px solid var(--border);
                    border-radius:12px;
                    background:rgba(16,185,129,0.10);
                    padding:12px;
                    margin-top:12px;
                }}
                .termux-cta strong{{display:block;margin-bottom:6px}}
                .termux-cta p{{margin:0 0 8px 0;color:var(--text)}}
                .termux-cta a{{color:#22c55e;font-weight:650;text-decoration:none}}
                .termux-cta a:hover{{text-decoration:underline}}
                .termux-links{{display:flex;flex-wrap:wrap;gap:10px}}
                .platform-cta{{
                    margin-top:12px;
                    border:1px solid var(--border);
                    border-radius:12px;
                    padding:12px;
                    background:rgba(124,58,237,0.10);
                }}
                .platform-cta p{{margin:0 0 8px 0;color:var(--text)}}
                .platform-cta a{{color:#c4b5fd;text-decoration:none;font-weight:650}}
                .platform-cta a:hover{{text-decoration:underline}}
                .platform-cmd{{
                    font-size:13px;
                    color:#e5e7eb;
                    margin-top:6px;
                    background:rgba(15,23,42,0.8);
                    border:1px solid var(--border);
                    border-radius:8px;
                    padding:10px;
                    overflow:auto;
                    font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;
                }}
                .code-wrap{{display:flex;gap:8px;align-items:stretch}}
                .code-wrap pre{{flex:1 1 auto;margin:0}}
                .copy-btn{{
                    width:auto;
                    padding:8px 12px;
                    margin-top:0;
                    border-radius:8px;
                    border:1px solid var(--border);
                    background:transparent;
                    color:var(--text);
                    box-shadow:none;
                }}
                .repo-cta{{
                    margin-top:12px;
                    border:1px solid var(--border);
                    border-radius:12px;
                    padding:12px;
                    background:rgba(59,130,246,0.08);
                }}
                .repo-cta p{{margin:0 0 6px 0;color:var(--text)}}
                .repo-cta a{{color:#60a5fa;text-decoration:none;font-weight:650}}
                .repo-cta a:hover{{text-decoration:underline}}
                .tutorial-cta{{
                    margin-top:12px;
                    border:1px solid var(--border);
                    border-radius:12px;
                    padding:12px;
                    background:rgba(14,165,233,0.08);
                }}
                .tutorial-cta p{{margin:0 0 8px 0;color:var(--text)}}
                .tutorial-cta a{{color:#67e8f9;text-decoration:none;font-weight:650}}
                .tutorial-cta a:hover{{text-decoration:underline}}
                .clone-line{{
                    font-size:13px;
                    color:#e5e7eb;
                    margin-top:6px;
                    background:rgba(15,23,42,0.8);
                    border:1px solid var(--border);
                    border-radius:8px;
                    padding:10px;
                    overflow:auto;
                    font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;
                }}
            </style>
        </head>
        <body>
            <div class="auth-shell">
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
                <section class="realm-wrap" aria-label="Administration domain">
                    <button type="button" class="realm-tab active" data-realm="campus">Campus</button>
                    <button type="button" class="realm-tab" data-realm="family">Family</button>
                    <button type="button" class="realm-tab" data-realm="corporate">Corporate</button>
                    <button type="button" class="realm-tab" data-realm="community">Community</button>
                    <button type="button" class="realm-tab" data-realm="government">Government</button>
                    <button type="button" class="realm-tab" data-realm="non-profit">Non-Profit</button>
                </section>
                <div id="realmDescription" class="realm-info"></div>
                <form method="post" action="{action}">
                                        <input id="realm" name="realm" type="hidden" value="campus" />
                    <fieldset class="auth-fields">
                        <input id="username" name="username" type="text" required minlength="3" maxlength="64" autocomplete="username" value="{safe_username}" placeholder="Username" />
                        <div class="password-wrap">
                            <input id="password" name="password" type="password" required minlength="12" autocomplete="{'new-password' if is_setup else 'current-password'}" placeholder="Password" />
                            <button class="password-toggle" type="button" data-target="password" aria-label="Show password">👁</button>
                        </div>
                        <button type="submit">{primary}</button>
                    </fieldset>
                </form>
                {policy_hint}
                {repo_block}
                {tutorial_block}
                {termux_block}
                <section id="platformCta" class="platform-cta">
                    <p id="platformMeta">Detecting your device environment for Ginto Tunnel setup...</p>
                    <a id="platformLink" href="https://github.com/oliverbob/gntl" target="_blank" rel="noopener noreferrer">Open Ginto Tunnel Repository</a>
                    <div class="code-wrap">
                        <pre class="platform-cmd"><code id="platformCmd">git clone https://github.com/oliverbob/gntl</code></pre>
                        <button class="copy-btn" type="button" data-copy-target="platformCmd">Copy</button>
                    </div>
                </section>
            </main>
            </div>
                        <script>
                            (function(){{
                                const tabs = Array.from(document.querySelectorAll('.realm-tab'));
                                const hidden = document.getElementById('realm');
                                const desc = document.getElementById('realmDescription');
                                const descriptions = {{
                                    campus: 'Campus: academic delivery, courses, classes, faculty coordination, and student success workflows.',
                                    family: 'Family: guardian-facing updates, consent flows, student progress visibility, and home-school collaboration.',
                                    corporate: 'Corporate: internship partnerships, industry mentors, placement pipelines, and workforce alignment.',
                                    community: 'Community: local stakeholders, civic collaboration, shared learning initiatives, and outreach programs.',
                                    government: 'Government: policy alignment, compliance reporting, institutional oversight, and public service integration.',
                                    'non-profit': 'Non-Profit: mission-driven programs, sponsorship coordination, volunteer engagement, and impact reporting.'
                                }};
                                function setRealm(value){{
                                    if (hidden) hidden.value = value;
                                    tabs.forEach((tab) => tab.classList.toggle('active', tab.dataset.realm === value));
                                    if (desc) desc.textContent = descriptions[value] || '';
                                }}
                                tabs.forEach((tab) => tab.addEventListener('click', () => setRealm(tab.dataset.realm)));
                                setRealm('campus');

                                function initPasswordToggles(){{
                                    const toggles = Array.from(document.querySelectorAll('.password-toggle'));
                                    toggles.forEach((toggle) => {{
                                        toggle.addEventListener('click', () => {{
                                            const targetId = toggle.getAttribute('data-target');
                                            const input = targetId ? document.getElementById(targetId) : null;
                                            if (!input) return;
                                            const isMasked = input.type === 'password';
                                            input.type = isMasked ? 'text' : 'password';
                                            toggle.setAttribute('aria-label', isMasked ? 'Hide password' : 'Show password');
                                        }});
                                    }});
                                }}

                                function initCopyButtons(){{
                                    const buttons = Array.from(document.querySelectorAll('.copy-btn'));
                                    buttons.forEach((btn) => {{
                                        btn.addEventListener('click', async () => {{
                                            const targetId = btn.getAttribute('data-copy-target');
                                            const target = targetId ? document.getElementById(targetId) : null;
                                            const text = target ? (target.textContent || '').trim() : '';
                                            if (!text) return;
                                            try {{
                                                await navigator.clipboard.writeText(text);
                                                const prev = btn.textContent;
                                                btn.textContent = 'Copied';
                                                setTimeout(() => (btn.textContent = prev || 'Copy'), 1200);
                                            }} catch (_err) {{
                                            }}
                                        }});
                                    }});
                                }}

                                function isAndroidDevice(){{
                                    const ua = (navigator.userAgent || '').toLowerCase();
                                    const uaData = navigator.userAgentData;
                                    if (uaData && Array.isArray(uaData.platforms)) {{
                                        if (uaData.platforms.some((p) => String(p || '').toLowerCase().includes('android'))) return true;
                                    }}
                                    if (uaData && typeof uaData.platform === 'string' && uaData.platform.toLowerCase().includes('android')) {{
                                        return true;
                                    }}
                                    return ua.includes('android');
                                }}

                                function parseAndroidMajor(uaValue){{
                                    const match = String(uaValue || '').match(/Android\s+([0-9]+)(?:\.([0-9]+))?/i);
                                    if (!match) return null;
                                    const major = parseInt(match[1], 10);
                                    return Number.isFinite(major) ? major : null;
                                }}

                                function detectPlatformFamily(){{
                                    const ua = (navigator.userAgent || '').toLowerCase();
                                    const platform = ((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '').toLowerCase();
                                    if (ua.includes('android') || platform.includes('android')) return 'android';
                                    if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ipod')) return 'ios';
                                    if (platform.includes('win') || ua.includes('windows')) return 'windows';
                                    if (platform.includes('mac') || ua.includes('mac os')) return 'macos';
                                    if (platform.includes('linux') || ua.includes('linux')) return 'linux';
                                    return 'unknown';
                                }}

                                function initPlatformRecommendations(){{
                                    const meta = document.getElementById('platformMeta');
                                    const link = document.getElementById('platformLink');
                                    const cmd = document.getElementById('platformCmd');
                                    const cta = document.getElementById('platformCta');
                                    if (!meta || !link || !cmd || !cta) return;

                                    const platform = detectPlatformFamily();
                                    if (platform === 'android') {{
                                        cta.style.display = 'none';
                                        return;
                                    }}
                                    if (platform === 'ios') {{
                                        cta.style.display = 'none';
                                        return;
                                    }}
                                    if (platform === 'windows') {{
                                        meta.textContent = 'Windows desktop detected. Install Git + Python, then clone Ginto Tunnel.';
                                        link.textContent = 'Open Ginto Tunnel Repository';
                                        link.href = 'https://github.com/oliverbob/gntl';
                                        cmd.textContent = 'git clone https://github.com/oliverbob/gntl';
                                        return;
                                    }}
                                    if (platform === 'macos') {{
                                        meta.textContent = 'macOS desktop detected. Install git/python (or brew), then clone Ginto Tunnel.';
                                        link.textContent = 'Open Ginto Tunnel Repository';
                                        link.href = 'https://github.com/oliverbob/gntl';
                                        cmd.textContent = 'git clone https://github.com/oliverbob/gntl';
                                        return;
                                    }}
                                    if (platform === 'linux') {{
                                        meta.textContent = 'Linux desktop detected. Clone Ginto Tunnel and run setup in your environment.';
                                        link.textContent = 'Open Ginto Tunnel Repository';
                                        link.href = 'https://github.com/oliverbob/gntl';
                                        cmd.textContent = 'git clone https://github.com/oliverbob/gntl';
                                        return;
                                    }}
                                    meta.textContent = 'Could not identify your platform. Open the repository and follow the setup instructions for your environment.';
                                    link.textContent = 'Open Ginto Tunnel Repository';
                                    link.href = 'https://github.com/oliverbob/gntl';
                                    cmd.textContent = 'git clone https://github.com/oliverbob/gntl';
                                }}

                                function androidMajorToApi(major){{
                                    const mapping = {{
                                        16: 36,
                                        15: 35,
                                        14: 34,
                                        13: 33,
                                        12: 31,
                                        11: 30,
                                        10: 29,
                                        9: 28,
                                        8: 26,
                                        7: 24,
                                        6: 23,
                                        5: 21
                                    }};
                                    return mapping[major] || null;
                                }}

                                function detectArchitecture(){{
                                    const ua = (navigator.userAgent || '').toLowerCase();
                                    if (ua.includes('arm64') || ua.includes('aarch64')) return 'arm64-v8a';
                                    if (ua.includes('armeabi') || ua.includes('armv7')) return 'armeabi-v7a';
                                    if (ua.includes('x86_64') || ua.includes('amd64')) return 'x86_64';
                                    if (ua.includes(' x86') || ua.includes('i686')) return 'x86';
                                    return 'universal';
                                }}

                                function pickBestAsset(assets, arch, apiLevel){{
                                    const apks = (assets || []).filter((asset) => String(asset.name || '').toLowerCase().endsWith('.apk'));
                                    if (!apks.length) return null;

                                    let best = null;
                                    let bestScore = -1;
                                    for (const asset of apks) {{
                                        const name = String(asset.name || '').toLowerCase();
                                        const apiMatch = name.match(/api\s*([0-9]+)/i);
                                        if (apiMatch && apiLevel) {{
                                            const requiredApi = parseInt(apiMatch[1], 10);
                                            if (Number.isFinite(requiredApi) && requiredApi > apiLevel) continue;
                                        }}

                                        let score = 0;
                                        if (name.includes(arch)) score += 100;
                                        if (name.includes('universal')) score += 80;
                                        if (name.includes('github')) score += 20;
                                        if (!name.includes('fdroid')) score += 10;
                                        if (score > bestScore) {{
                                            best = asset;
                                            bestScore = score;
                                        }}
                                    }}

                                    return best || apks[0];
                                }}

                                async function getAndroidMajorFromUAData(){{
                                    try {{
                                        const uaData = navigator.userAgentData;
                                        if (!uaData || !uaData.getHighEntropyValues) return null;
                                        const values = await uaData.getHighEntropyValues(['platformVersion']);
                                        const raw = String(values.platformVersion || '').trim();
                                        if (!raw) return null;
                                        const major = parseInt(raw.split('.')[0], 10);
                                        return Number.isFinite(major) && major > 0 ? major : null;
                                    }} catch (_err) {{
                                        return null;
                                    }}
                                }}

                                async function initTermuxDownloadCta(){{
                                    const termuxCta = document.getElementById('termuxCta');
                                    const termuxMeta = document.getElementById('termuxDetectMeta');
                                    const termuxAutoLink = document.getElementById('termuxAutoLink');
                                    if (!termuxCta || !termuxMeta || !termuxAutoLink) return;

                                    const platform = detectPlatformFamily();
                                    if (platform === 'ios') {{
                                        termuxMeta.textContent = 'Use iSH from link above for iOS.';
                                        termuxAutoLink.textContent = 'Download';
                                        termuxAutoLink.href = 'https://ish.app';
                                        return;
                                    }}
                                    if (platform !== 'android') {{
                                        termuxCta.style.display = 'none';
                                        return;
                                    }}

                                    if (!isAndroidDevice()) {{
                                        termuxMeta.textContent = 'Android not detected in this browser. Open this page on Android to enable autodetected Termux download.';
                                        termuxAutoLink.textContent = 'Download';
                                        termuxAutoLink.href = 'https://github.com/termux/termux-app/releases/latest';
                                        return;
                                    }}

                                    const uaMajor = parseAndroidMajor(navigator.userAgent || '');
                                    const uaDataMajor = await getAndroidMajorFromUAData();
                                    const androidMajor = uaDataMajor || uaMajor;
                                    const apiLevel = androidMajorToApi(androidMajor);
                                    const arch = detectArchitecture();

                                    try {{
                                        const resp = await fetch('https://api.github.com/repos/termux/termux-app/releases/latest', {{ headers: {{ 'Accept': 'application/vnd.github+json' }} }});
                                        if (!resp.ok) throw new Error('release lookup failed');
                                        const release = await resp.json();
                                        const bestAsset = pickBestAsset(release.assets || [], arch, apiLevel);
                                        if (bestAsset && bestAsset.browser_download_url) {{
                                            termuxAutoLink.href = bestAsset.browser_download_url;
                                            const versionText = androidMajor ? `Android ${{androidMajor}}` : 'Android';
                                            const apiText = apiLevel ? `API ${{apiLevel}}` : 'API unknown';
                                            termuxAutoLink.textContent = 'Download';
                                            termuxMeta.textContent = `Detected ${{versionText}} (${{apiText}}) on ${{arch}}. Suggested package: ${{bestAsset.name}}`;
                                            return;
                                        }}
                                    }} catch (_err) {{
                                    }}

                                    termuxAutoLink.href = 'https://github.com/termux/termux-app/releases/latest';
                                    termuxAutoLink.textContent = 'Download';
                                    termuxMeta.textContent = 'Detected Android device. Could not fetch exact package details, so latest Termux release is linked.';
                                }}

                                initPasswordToggles();
                                initCopyButtons();
                                initTermuxDownloadCta();
                                initPlatformRecommendations();
                            }})();
                        </script>
        </body>
        </html>
        '''


def _q(value):
    return str(value).replace('\\', '\\\\').replace('"', '\\"')


def _tutorial_page() -> str:
    return '''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width,initial-scale=1" />
            <title>Ginto Cross-Platform Tutorial</title>
            <style>
                :root{--bg:#0b1020;--card:#121a30;--muted:#9fb0c8;--text:#e6eef8;--border:rgba(255,255,255,.12);--accent:#60a5fa}
                html,body{height:100%;margin:0;background:var(--bg);color:var(--text);font-family:Inter,Segoe UI,Roboto,Arial,sans-serif}
                .wrap{max-width:900px;margin:22px auto;padding:16px}
                .card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:16px}
                h1{margin:0 0 8px 0}
                p,li{color:var(--muted)}
                a{color:var(--accent);text-decoration:none}
                a:hover{text-decoration:underline}
                .chips{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0 12px 0}
                .chip{padding:8px 10px;border:1px solid var(--border);border-radius:999px;background:transparent;color:var(--text)}
                .platform{display:none;border:1px solid var(--border);border-radius:12px;padding:12px;margin-top:10px}
                .platform.active{display:block}
                .code-row{display:flex;gap:8px;align-items:stretch;margin-top:8px}
                pre{margin:0;flex:1 1 auto;padding:10px;border:1px solid var(--border);border-radius:8px;background:rgba(15,23,42,.8);overflow:auto}
                .copy-btn{padding:8px 12px;border:1px solid var(--border);border-radius:8px;background:transparent;color:var(--text);cursor:pointer}
                .other{margin-top:12px;padding-top:10px;border-top:1px solid var(--border)}
                .download-choice{margin:8px 0}
                .download-choice p{margin:0 0 6px 0}
                .download-choice a{margin-right:10px}
            </style>
        </head>
        <body>
            <div class="wrap">
                <div class="card">
                    <h1>Cross-Platform Setup Tutorial</h1>
                    <p id="detectedText">Detecting your OS...</p>
                    <div class="chips">
                        <a class="chip" href="#android" data-platform-link="android">Android</a>
                        <a class="chip" href="#ios" data-platform-link="ios">iOS</a>
                        <a class="chip" href="#windows" data-platform-link="windows">Windows</a>
                        <a class="chip" href="#macos" data-platform-link="macos">macOS</a>
                        <a class="chip" href="#linux" data-platform-link="linux">Linux</a>
                    </div>

                    <section id="platform-android" class="platform">
                        <h3>Android (Termux) — Full Walkthrough</h3>
                        <ol>
                            <li>Install Termux from GitHub Releases.</li>
                            <li>Open Termux once installation is complete.</li>
                            <li>Update and upgrade packages.</li>
                            <li>Install Git (and optionally curl).</li>
                            <li>Clone the repository.</li>
                            <li>Start Ginto from the project folder.</li>
                            <li>Open your browser at <strong>http://localhost:2026</strong>.</li>
                        </ol>
                        <div class="download-choice">
                            <p id="androidDownloadNote">Your Android version needs this file, or you can Download it Manually from the same official source.</p>
                            <a id="androidAutoDownload" href="https://github.com/termux/termux-app/releases/latest" target="_blank" rel="noopener noreferrer">Your mobile version needs this version: termux.apk</a>
                            <a id="androidManualDownload" href="https://github.com/termux/termux-app/releases" target="_blank" rel="noopener noreferrer">Download Manually</a>
                        </div>
                        <div class="code-row"><pre><code id="android-step1">pkg update -y && pkg upgrade -y</code></pre><button class="copy-btn" data-copy-target="android-step1" type="button">Copy</button></div>
                        <div class="code-row"><pre><code id="android-step2">pkg install -y git curl</code></pre><button class="copy-btn" data-copy-target="android-step2" type="button">Copy</button></div>
                        <div class="code-row"><pre><code id="android-step3">git clone https://github.com/oliverbob/gntl</code></pre><button class="copy-btn" data-copy-target="android-step3" type="button">Copy</button></div>
                        <div class="code-row"><pre><code id="android-step4">cd gntl && ./run.sh</code></pre><button class="copy-btn" data-copy-target="android-step4" type="button">Copy</button></div>
                        <div class="code-row"><pre><code id="android-step5">http://localhost:2026</code></pre><button class="copy-btn" data-copy-target="android-step5" type="button">Copy</button></div>
                    </section>

                    <section id="platform-ios" class="platform">
                        <h3>iOS (iSH)</h3>
                        <div class="download-choice">
                            <p>Your iOS version needs iSH shell, or you can Download it Manually from the same official source.</p>
                            <a id="iosAutoDownload" href="https://ish.app" target="_blank" rel="noopener noreferrer">Your mobile version needs this version: iSH</a>
                            <a id="iosManualDownload" href="https://ish.app" target="_blank" rel="noopener noreferrer">Download Manually</a>
                        </div>
                        <p>Install iSH shell, then run:</p>
                        <div class="code-row"><pre><code id="ios-step">apk update && apk add git php84 && git clone https://github.com/oliverbob/gntl && cd gntl && ./run.sh</code></pre><button class="copy-btn" data-copy-target="ios-step" type="button">Copy</button></div>
                    </section>

                    <section id="platform-windows" class="platform">
                        <h3>Windows</h3>
                        <p>Install Git + Python, then run:</p>
                        <div class="code-row"><pre><code id="win-step">git clone https://github.com/oliverbob/gntl
cd gntl
./run.sh</code></pre><button class="copy-btn" data-copy-target="win-step" type="button">Copy</button></div>
                    </section>

                    <section id="platform-macos" class="platform">
                        <h3>macOS</h3>
                        <p>Install Git/Python (or Homebrew), then run:</p>
                        <div class="code-row"><pre><code id="mac-step">git clone https://github.com/oliverbob/gntl
cd gntl
./run.sh</code></pre><button class="copy-btn" data-copy-target="mac-step" type="button">Copy</button></div>
                    </section>

                    <section id="platform-linux" class="platform">
                        <h3>Linux</h3>
                        <p>Use your package manager for git/python if needed, then run:</p>
                        <div class="code-row"><pre><code id="linux-step">git clone https://github.com/oliverbob/gntl
cd gntl
./run.sh</code></pre><button class="copy-btn" data-copy-target="linux-step" type="button">Copy</button></div>
                    </section>

                    <div class="other">
                        <p><strong>Other platforms:</strong> <span id="otherLinks"></span></p>
                        <p><a href="/login">Back to Login</a></p>
                    </div>
                </div>
            </div>
            <script>
                (function(){
                    function detectPlatform(){
                        const ua = (navigator.userAgent || '').toLowerCase();
                        const platform = ((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '').toLowerCase();
                        if (ua.includes('android') || platform.includes('android')) return 'android';
                        if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ipod')) return 'ios';
                        if (platform.includes('win') || ua.includes('windows')) return 'windows';
                        if (platform.includes('mac') || ua.includes('mac os')) return 'macos';
                        if (platform.includes('linux') || ua.includes('linux')) return 'linux';
                        return 'linux';
                    }

                    const map = { android: 'Android', ios: 'iOS', windows: 'Windows', macos: 'macOS', linux: 'Linux' };

                    function showPlatform(name){
                        document.querySelectorAll('.platform').forEach((el)=>el.classList.remove('active'));
                        const section = document.getElementById('platform-' + name);
                        if (section) section.classList.add('active');
                        const detected = document.getElementById('detectedText');
                        if (detected) detected.textContent = 'Showing tutorial for: ' + (map[name] || name);
                        const other = Object.keys(map).filter((k)=>k !== name).map((k)=>'<a href="#' + k + '" data-platform-link="' + k + '">' + map[k] + '</a>');
                        const otherLinks = document.getElementById('otherLinks');
                        if (otherLinks) otherLinks.innerHTML = other.join(' · ');
                    }

                    function initCopyButtons(){
                        document.querySelectorAll('.copy-btn').forEach((btn)=>{
                            btn.addEventListener('click', async ()=>{
                                const targetId = btn.getAttribute('data-copy-target');
                                const target = targetId ? document.getElementById(targetId) : null;
                                const text = target ? (target.textContent || '').trim() : '';
                                if (!text) return;
                                try {
                                    await navigator.clipboard.writeText(text);
                                    const old = btn.textContent;
                                    btn.textContent = 'Copied';
                                    setTimeout(()=>btn.textContent = old || 'Copy', 1200);
                                } catch (_err) {
                                }
                            });
                        });
                    }

                    function parseAndroidMajor(uaValue){
                        const match = String(uaValue || '').match(/Android\s+([0-9]+)(?:\.([0-9]+))?/i);
                        if (!match) return null;
                        const major = parseInt(match[1], 10);
                        return Number.isFinite(major) ? major : null;
                    }

                    function androidMajorToApi(major){
                        const mapping = {16:36,15:35,14:34,13:33,12:31,11:30,10:29,9:28,8:26,7:24,6:23,5:21};
                        return mapping[major] || null;
                    }

                    function detectArchitecture(){
                        const ua = (navigator.userAgent || '').toLowerCase();
                        if (ua.includes('arm64') || ua.includes('aarch64')) return 'arm64-v8a';
                        if (ua.includes('armeabi') || ua.includes('armv7')) return 'armeabi-v7a';
                        if (ua.includes('x86_64') || ua.includes('amd64')) return 'x86_64';
                        if (ua.includes(' x86') || ua.includes('i686')) return 'x86';
                        return 'universal';
                    }

                    function pickBestAsset(assets, arch, apiLevel){
                        const apks = (assets || []).filter((asset) => String(asset.name || '').toLowerCase().endsWith('.apk'));
                        if (!apks.length) return null;
                        let best = null;
                        let bestScore = -1;
                        for (const asset of apks){
                            const name = String(asset.name || '').toLowerCase();
                            const apiMatch = name.match(/api\s*([0-9]+)/i);
                            if (apiMatch && apiLevel){
                                const requiredApi = parseInt(apiMatch[1], 10);
                                if (Number.isFinite(requiredApi) && requiredApi > apiLevel) continue;
                            }
                            let score = 0;
                            if (name.includes(arch)) score += 100;
                            if (name.includes('universal')) score += 80;
                            if (!name.includes('fdroid')) score += 10;
                            if (score > bestScore){
                                best = asset;
                                bestScore = score;
                            }
                        }
                        return best || apks[0];
                    }

                    async function getAndroidMajorFromUAData(){
                        try {
                            const uaData = navigator.userAgentData;
                            if (!uaData || !uaData.getHighEntropyValues) return null;
                            const values = await uaData.getHighEntropyValues(['platformVersion']);
                            const raw = String(values.platformVersion || '').trim();
                            if (!raw) return null;
                            const major = parseInt(raw.split('.')[0], 10);
                            return Number.isFinite(major) && major > 0 ? major : null;
                        } catch (_err) {
                            return null;
                        }
                    }

                    async function initMobileDownloadChoices(){
                        const androidAuto = document.getElementById('androidAutoDownload');
                        const androidNote = document.getElementById('androidDownloadNote');
                        if (androidAuto && androidNote){
                            const uaMajor = parseAndroidMajor(navigator.userAgent || '');
                            const uaDataMajor = await getAndroidMajorFromUAData();
                            const androidMajor = uaDataMajor || uaMajor;
                            const apiLevel = androidMajorToApi(androidMajor);
                            const arch = detectArchitecture();
                            try {
                                const resp = await fetch('https://api.github.com/repos/termux/termux-app/releases/latest', { headers: { 'Accept': 'application/vnd.github+json' } });
                                if (!resp.ok) throw new Error('release lookup failed');
                                const release = await resp.json();
                                const bestAsset = pickBestAsset(release.assets || [], arch, apiLevel);
                                if (bestAsset && bestAsset.browser_download_url) {
                                    androidAuto.href = bestAsset.browser_download_url;
                                    androidAuto.textContent = "Your mobile version needs this version: " + bestAsset.name;
                                    androidNote.textContent = 'Your Android version needs ' + bestAsset.name + ', or you can Download it Manually from the same official source.';
                                }
                            } catch (_err) {
                                androidAuto.href = 'https://github.com/termux/termux-app/releases/latest';
                            }
                        }
                    }

                    document.addEventListener('click', (event)=>{
                        const target = event.target;
                        if (!(target instanceof HTMLElement)) return;
                        const platform = target.getAttribute('data-platform-link');
                        if (!platform) return;
                        event.preventDefault();
                        showPlatform(platform);
                    });

                    initCopyButtons();
                    initMobileDownloadChoices();
                    showPlatform(detectPlatform());
                })();
            </script>
        </body>
        </html>
    '''


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
            '/tutorial',
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

    @app.get('/terminal')
    async def terminal_page():
        terminal_file = os.path.join(templates_dir, 'terminal.html')
        if os.path.exists(terminal_file):
            return HTMLResponse(open(terminal_file, 'r').read())
        raise HTTPException(404, 'Terminal UI not found')

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
        try:
            username = _normalize_username(username_raw)
        except ValueError as e:
            return HTMLResponse(_auth_page('setup', str(e), username_raw), status_code=400)
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

    @app.get('/tutorial')
    async def tutorial_page():
        return HTMLResponse(_tutorial_page())

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
        try:
            username = _normalize_username(username_raw)
        except ValueError as e:
            raise HTTPException(400, str(e))
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

    @app.post('/api/admin/terminal/exec')
    async def admin_terminal_exec(req: Request):
        body = await req.json()
        command = str((body.get('command') or '')).strip()
        if not command:
            raise HTTPException(400, 'command is required')
        if len(command) > 2000:
            raise HTTPException(400, 'command is too long')

        timed_out = False
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=os.path.dirname(__file__),
            env={
                **os.environ,
                'TERM': os.environ.get('TERM', 'xterm-256color'),
            },
        )

        output_bytes = b''
        exit_code = None
        try:
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=TERMINAL_COMMAND_TIMEOUT_SECONDS,
            )
            output_bytes = stdout or b''
            exit_code = process.returncode
        except asyncio.TimeoutError:
            timed_out = True
            process.kill()
            stdout, _ = await process.communicate()
            output_bytes = (stdout or b'') + b'\n[terminated: command timed out]\n'
            exit_code = 124

        output = output_bytes.decode('utf-8', errors='replace')
        truncated = False
        if len(output) > TERMINAL_MAX_OUTPUT_CHARS:
            output = output[:TERMINAL_MAX_OUTPUT_CHARS] + '\n[truncated]\n'
            truncated = True

        return {
            'ok': exit_code == 0,
            'command': command,
            'exitCode': exit_code,
            'output': output,
            'timedOut': timed_out,
            'truncated': truncated,
            'cwd': os.path.dirname(__file__),
        }

    # REST API
    @app.get('/api/instances')
    async def list_instances(request: Request):
        out = {}
        owner = _request_username(request)
        for id, inst in manager.instances.items():
            if _instance_owner(inst) != owner:
                continue
            pid = None
            if inst.process and inst.process.poll() is None:
                pid = inst.process.pid
            elif getattr(inst, 'external_pid', None):
                pid = inst.external_pid
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

        create_http_raw = str(os.environ.get('GNTL_ENABLE_HTTP_ON_CREATE', '0') or '').strip().lower()
        create_http = create_http_raw in ('1', 'true', 'yes', 'on')

        default_local_port = _env_int(
            'GNTL_INSTANCE_HTTP_PORT' if create_http else 'GNTL_INSTANCE_HTTPS_PORT',
            APP_HTTP_PORT if create_http else APP_HTTPS_PORT,
        )

        local_http_port_raw = body.get('localHttpPort')
        if local_http_port_raw in (None, ''):
            local_http_port_raw = body.get('localPort')
        if local_http_port_raw in (None, ''):
            local_http_port_raw = default_local_port

        local_https_port_raw = body.get('localHttpsPort')
        if local_https_port_raw in (None, ''):
            local_https_port_raw = local_http_port_raw

        local_http_port = local_http_port_raw
        local_https_port = local_https_port_raw
        if not group_id:
            raise HTTPException(400, 'id required')

        try:
            local_http_port = int(local_http_port)
        except Exception:
            local_http_port = 80
        if local_http_port <= 0 or local_http_port > 65535:
            local_http_port = 80

        try:
            local_https_port = int(local_https_port)
        except Exception:
            local_https_port = local_http_port
        if local_https_port <= 0 or local_https_port > 65535:
            local_https_port = local_http_port

        create_protocols = ('http', 'https') if create_http else ('https',)

        create_ids = [
            _instance_id_for_owner(owner, group_id, protocol)
            for protocol in create_protocols
        ]
        for pair_id in create_ids:
            if pair_id in manager.instances:
                raise HTTPException(409, f'instance already exists: {pair_id}')

        configs_dir = _configs_dir()
        frpc_path = os.path.abspath(binpath or os.path.join(BASE_DIR, 'bin', 'frpc'))
        can_auto_start = os.path.exists(frpc_path)
        created = []

        for protocol in create_protocols:
            instance_id = _instance_id_for_owner(owner, group_id, protocol)
            protocol_proxy_name = f"{proxy_name}-{protocol}"
            protocol_local_port = local_http_port if protocol == 'http' else local_https_port
            cfg_text = render_frpc_config(
                server_addr=server_addr,
                server_port=int(server_port),
                auth_token=DEFAULT_AUTH_TOKEN,
                proxy_name=protocol_proxy_name,
                local_port=int(protocol_local_port),
                subdomain=subdomain,
                protocol=protocol,
            )
            cfg_path = os.path.join(configs_dir, f"{instance_id}.toml")
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
                'localPort': int(protocol_local_port),
                'localHttpPort': int(local_http_port),
                'localHttpsPort': int(local_https_port),
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

            auto_started = False
            auto_start_error = None
            if can_auto_start:
                auto_started = bool(manager.start_instance(instance_id, frpc_path))
                if not auto_started:
                    auto_start_error = manager.get_instance_last_error(instance_id) or 'failed to auto-start instance'
            else:
                auto_start_error = 'frpc binary not found'

            created.append({
                'id': instance_id,
                'groupId': group_id,
                'owner': owner,
                'protocol': protocol,
                'localPort': int(protocol_local_port),
                'configPath': cfg_path,
                'autoStarted': auto_started,
                'autoStartError': auto_start_error,
            })

        return {
            'ok': True,
            'groupId': group_id,
            'created': created,
        }

    @app.post('/api/instances/{id}/start')
    async def start_instance(id: str, request: Request):
        path = os.path.abspath(binpath or os.path.join(BASE_DIR, 'bin', 'frpc'))
        if not os.path.exists(path):
            raise HTTPException(500, 'frpc binary not found')
        inst = manager.instances.get(id)
        if not inst:
            raise HTTPException(404, 'not found')
        if _instance_owner(inst) != _request_username(request):
            raise HTTPException(403, 'forbidden')
        ok = manager.start_instance(id, path)
        return {
            'ok': bool(ok),
            'error': (manager.get_instance_last_error(id) if not ok else None),
        }

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
        path = os.path.abspath(binpath or os.path.join(BASE_DIR, 'bin', 'frpc'))
        if not os.path.exists(path):
            raise HTTPException(500, 'frpc binary not found')
        inst = manager.instances.get(id)
        if not inst:
            raise HTTPException(404, 'not found')
        if _instance_owner(inst) != _request_username(request):
            raise HTTPException(403, 'forbidden')
        ok = manager.restart_instance(id, path)
        return {
            'ok': bool(ok),
            'error': (manager.get_instance_last_error(id) if not ok else None),
        }

    @app.delete('/api/instances/{id}')
    async def delete_instance(id: str, request: Request):
        inst = manager.instances.get(id)
        if not inst:
            raise HTTPException(404, 'not found')
        if _instance_owner(inst) != _request_username(request):
            raise HTTPException(403, 'forbidden')
        ok = manager.delete_instance(id)
        cleanup_result = manager.cleanup_deleted_instances()
        return {
            'ok': bool(ok),
            'cleanup': cleanup_result,
        }

    @app.post('/api/instances/cleanup-deleted')
    async def cleanup_deleted_instances(_request: Request):
        result = manager.cleanup_deleted_instances()
        return {
            'ok': True,
            'result': result,
        }

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
        owner = _session_username_from_cookie_header(ws.headers.get('cookie', '') or '')
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

    @app.websocket('/ws/terminal')
    async def ws_terminal(ws: WebSocket):
        await ws.accept()
        owner = _session_username_from_cookie_header(ws.headers.get('cookie', '') or '')
        if not owner:
            await ws.send_text('\r\n[authentication required]\r\n')
            await ws.close()
            return

        shell = os.environ.get('SHELL') or '/bin/bash'
        master_fd = None
        process = None
        try:
            master_fd, slave_fd = pty.openpty()
            env = {
                **os.environ,
                'TERM': os.environ.get('TERM', 'xterm-256color'),
                'COLORTERM': 'truecolor',
                'GNTL_WEB_TERMINAL_USER': owner,
            }
            process = subprocess.Popen(
                [shell],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                cwd=os.path.dirname(__file__),
                env=env,
                preexec_fn=os.setsid,
                close_fds=True,
            )
            os.close(slave_fd)

            def _resize(cols: int, rows: int):
                if not master_fd:
                    return
                if cols < 1 or rows < 1:
                    return
                fcntl.ioctl(master_fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))

            async def _reader():
                while True:
                    if process and process.poll() is not None:
                        break
                    ready, _, _ = await asyncio.to_thread(select.select, [master_fd], [], [], 0.2)
                    if not ready:
                        continue
                    try:
                        data = os.read(master_fd, 4096)
                    except OSError:
                        break
                    if not data:
                        break
                    await ws.send_text(data.decode('utf-8', errors='replace'))
                code = process.poll() if process else None
                await ws.send_text(f'\r\n[terminal exited: {code}]\r\n')

            async def _writer():
                while True:
                    raw = await ws.receive_text()
                    try:
                        msg = json.loads(raw)
                    except Exception:
                        msg = {'type': 'input', 'data': raw}

                    msg_type = str(msg.get('type') or '').strip().lower()
                    if msg_type == 'resize':
                        cols = int(msg.get('cols') or 0)
                        rows = int(msg.get('rows') or 0)
                        _resize(cols, rows)
                        continue

                    if msg_type == 'input':
                        text = str(msg.get('data') or '')
                        if text:
                            os.write(master_fd, text.encode('utf-8', errors='ignore'))

            await asyncio.gather(_reader(), _writer())
        except Exception:
            try:
                await ws.close()
            except Exception:
                pass
        finally:
            if process and process.poll() is None:
                try:
                    process.terminate()
                except Exception:
                    pass
            if master_fd is not None:
                try:
                    os.close(master_fd)
                except Exception:
                    pass

    @app.get('/_status')
    def status():
        return {'ok': True}

    return app


if __name__ == '__main__':
    app = build_app()
    tls_options, tls_enabled = resolve_tls_options()

    if tls_enabled:
        print(f'TLS enabled for web admin on https://{APP_HOST}:{APP_HTTPS_PORT}')
        print(f'HTTP mirror enabled for web admin on http://{APP_HOST}:{APP_HTTP_PORT}')

        async def run_dual_servers():
            https_server = uvicorn.Server(
                uvicorn.Config(
                    app,
                    host=APP_HOST,
                    port=APP_HTTPS_PORT,
                    **tls_options,
                )
            )
            http_server = uvicorn.Server(
                uvicorn.Config(
                    app,
                    host=APP_HOST,
                    port=APP_HTTP_PORT,
                )
            )
            await asyncio.gather(https_server.serve(), http_server.serve())

        asyncio.run(run_dual_servers())
    else:
        print(f'TLS disabled for web admin on http://{APP_HOST}:{APP_HTTP_PORT}')
        uvicorn.run(app, host=APP_HOST, port=APP_HTTP_PORT)
