<?php
session_start();

define('SESSION_KEY', 'gntl_mobile_user');

function app_root(): string {
    return dirname(__DIR__);
}

function db_path(): string {
    $configs = app_root() . '/configs';
    if (!is_dir($configs)) {
        mkdir($configs, 0775, true);
    }
    return $configs . '/webadmin_mobile.sqlite3';
}

function db(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $pdo = new PDO('sqlite:' . db_path());
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('CREATE TABLE IF NOT EXISTS admin_auth (id INTEGER PRIMARY KEY CHECK (id = 1), username TEXT NOT NULL, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)');
    return $pdo;
}

function has_password(): bool {
    $stmt = db()->query('SELECT 1 FROM admin_auth WHERE id = 1');
    return (bool) $stmt->fetchColumn();
}

function setup_password(string $username, string $password): void {
    $hash = password_hash($password, PASSWORD_DEFAULT);
    $now = time();
    $stmt = db()->prepare('INSERT INTO admin_auth (id, username, password_hash, created_at, updated_at) VALUES (1, :username, :password_hash, :created_at, :updated_at) ON CONFLICT(id) DO UPDATE SET username = excluded.username, password_hash = excluded.password_hash, updated_at = excluded.updated_at');
    $stmt->execute([
        ':username' => $username,
        ':password_hash' => $hash,
        ':created_at' => $now,
        ':updated_at' => $now,
    ]);
}

function verify_password(string $password): bool {
    $stmt = db()->query('SELECT password_hash FROM admin_auth WHERE id = 1');
    $hash = $stmt->fetchColumn();
    if (!$hash) {
        return false;
    }
    return password_verify($password, $hash);
}

function current_user(): ?string {
    $value = $_SESSION[SESSION_KEY] ?? null;
    return is_string($value) && $value !== '' ? $value : null;
}

function require_length(string $value, int $min): bool {
    return mb_strlen(trim($value)) >= $min;
}

function render_tutorial_page(): string {
    return <<<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Ginto Cross-Platform Tutorial</title>
  <style>
    :root{--bg:#0b1020;--card:#121a30;--muted:#9fb0c8;--text:#e6eef8;--border:rgba(255,255,255,.12);--accent:#86b7ff}
    html,body{height:100%;margin:0;background:var(--bg);color:var(--text);font-family:Inter,Segoe UI,Roboto,Arial,sans-serif}
    .wrap{max-width:900px;margin:20px auto;padding:16px}
    .card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:16px}
    p,li{color:var(--muted)} a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
    .chips{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px}
    .chip{padding:8px 10px;border:1px solid var(--border);border-radius:999px;background:transparent;color:var(--text)}
    .platform{display:none;border:1px solid var(--border);border-radius:12px;padding:12px;margin-top:10px}
    .platform.active{display:block}
    .code-row{display:flex;gap:8px;align-items:stretch;margin-top:8px}
    pre{margin:0;flex:1 1 auto;padding:10px;border:1px solid var(--border);border-radius:8px;background:rgba(15,23,42,.8);overflow:auto}
    .copy-btn{padding:8px 12px;border:1px solid var(--border);border-radius:8px;background:transparent;color:var(--text);cursor:pointer}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h2>Cross-Platform Setup Tutorial</h2>
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
          <li>Open Termux.</li>
          <li>Run update and upgrade.</li>
          <li>Install Git (and optionally curl).</li>
          <li>Clone the repository.</li>
          <li>Start Ginto.</li>
          <li>Open <strong>http://localhost:2026</strong> in browser.</li>
        </ol>
        <p><a href="https://github.com/termux/termux-app/releases" target="_blank" rel="noopener noreferrer">Download Termux</a></p>
        <div class="code-row"><pre><code id="android-step1">pkg update -y && pkg upgrade -y</code></pre><button class="copy-btn" data-copy-target="android-step1" type="button">Copy</button></div>
        <div class="code-row"><pre><code id="android-step2">pkg install -y git curl</code></pre><button class="copy-btn" data-copy-target="android-step2" type="button">Copy</button></div>
        <div class="code-row"><pre><code id="android-step3">git clone https://github.com/oliverbob/gntl</code></pre><button class="copy-btn" data-copy-target="android-step3" type="button">Copy</button></div>
        <div class="code-row"><pre><code id="android-step4">cd gntl && ./run.sh</code></pre><button class="copy-btn" data-copy-target="android-step4" type="button">Copy</button></div>
        <div class="code-row"><pre><code id="android-step5">http://localhost:2026</code></pre><button class="copy-btn" data-copy-target="android-step5" type="button">Copy</button></div>
      </section>
      <section id="platform-ios" class="platform">
        <h3>iOS</h3>
        <div class="code-row"><pre><code id="ios-step">apk update && apk add git php84 && git clone https://github.com/oliverbob/gntl && cd gntl && ./run.sh</code></pre><button class="copy-btn" data-copy-target="ios-step" type="button">Copy</button></div>
      </section>
      <section id="platform-windows" class="platform">
        <h3>Windows</h3>
        <div class="code-row"><pre><code id="win-step">git clone https://github.com/oliverbob/gntl
cd gntl
./run.sh</code></pre><button class="copy-btn" data-copy-target="win-step" type="button">Copy</button></div>
      </section>
      <section id="platform-macos" class="platform">
        <h3>macOS</h3>
        <div class="code-row"><pre><code id="mac-step">git clone https://github.com/oliverbob/gntl
cd gntl
./run.sh</code></pre><button class="copy-btn" data-copy-target="mac-step" type="button">Copy</button></div>
      </section>
      <section id="platform-linux" class="platform">
        <h3>Linux</h3>
        <div class="code-row"><pre><code id="linux-step">git clone https://github.com/oliverbob/gntl
cd gntl
./run.sh</code></pre><button class="copy-btn" data-copy-target="linux-step" type="button">Copy</button></div>
      </section>

      <p><strong>Other platforms:</strong> <span id="otherLinks"></span></p>
      <p><a href="/">Back to Login</a></p>
    </div>
  </div>
  <script>
    (function(){
      function detectPlatform(){
        const ua=(navigator.userAgent||'').toLowerCase();
        const platform=((navigator.userAgentData&&navigator.userAgentData.platform)||navigator.platform||'').toLowerCase();
        if(ua.includes('android')||platform.includes('android')) return 'android';
        if(ua.includes('iphone')||ua.includes('ipad')||ua.includes('ipod')) return 'ios';
        if(platform.includes('win')||ua.includes('windows')) return 'windows';
        if(platform.includes('mac')||ua.includes('mac os')) return 'macos';
        if(platform.includes('linux')||ua.includes('linux')) return 'linux';
        return 'linux';
      }
      const map={android:'Android',ios:'iOS',windows:'Windows',macos:'macOS',linux:'Linux'};
      function showPlatform(name){
        document.querySelectorAll('.platform').forEach((el)=>el.classList.remove('active'));
        const section=document.getElementById('platform-'+name);
        if(section) section.classList.add('active');
        const detected=document.getElementById('detectedText');
        if(detected) detected.textContent='Showing tutorial for: '+(map[name]||name);
        const other=Object.keys(map).filter((k)=>k!==name).map((k)=>'<a href="#'+k+'" data-platform-link="'+k+'">'+map[k]+'</a>');
        const target=document.getElementById('otherLinks');
        if(target) target.innerHTML=other.join(' · ');
      }
      function initCopyButtons(){
        document.querySelectorAll('.copy-btn').forEach((btn)=>{
          btn.addEventListener('click', async ()=>{
            const id = btn.getAttribute('data-copy-target');
            const code = id ? document.getElementById(id) : null;
            const text = code ? (code.textContent || '').trim() : '';
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
      document.addEventListener('click',(e)=>{
        const t=e.target;
        if(!(t instanceof HTMLElement)) return;
        const p=t.getAttribute('data-platform-link');
        if(!p) return;
        e.preventDefault();
        showPlatform(p);
      });
      initCopyButtons();
      showPlatform(detectPlatform());
    })();
  </script>
</body>
</html>
HTML;
}

$uriPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
if ($uriPath === '/tutorial') {
    echo render_tutorial_page();
    exit;
}

$error = '';
$mode = has_password() ? 'login' : 'setup';

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'logout') {
        unset($_SESSION[SESSION_KEY]);
        header('Location: /');
        exit;
    }

    if ($action === 'setup') {
        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');

        if (!require_length($username, 3)) {
            $error = 'Username must be at least 3 characters.';
        } elseif (strlen($password) < 8) {
            $error = 'Password must be at least 8 characters.';
        } else {
            setup_password($username, $password);
            $_SESSION[SESSION_KEY] = $username;
            header('Location: /');
            exit;
        }
    }

    if ($action === 'login') {
        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');

        if (!verify_password($password)) {
            $error = 'Invalid credentials.';
        } else {
            $_SESSION[SESSION_KEY] = $username !== '' ? $username : 'admin';
            header('Location: /');
            exit;
        }
    }
}

$user = current_user();
$platform = PHP_OS_FAMILY . ' / ' . php_uname('s');
?><!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Ginto Mobile Runtime</title>
  <style>
    :root { --bg:#0b1020; --card:#121a30; --text:#e6eef8; --muted:#9fb0c8; --accent:#3b82f6; --accent2:#7c3aed; --danger:#ef4444; --border:rgba(255,255,255,0.12); }
    html,body{height:100%;margin:0;background:var(--bg);color:var(--text);font-family:Inter,Segoe UI,Roboto,Arial,sans-serif}
    .wrap{max-width:740px;margin:24px auto;padding:16px}
    .card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px;box-shadow:0 14px 32px rgba(2,6,23,.45)}
    h1{margin:0 0 8px 0;font-size:24px}
    p{margin:0 0 12px 0;color:var(--muted)}
    .alert{background:rgba(239,68,68,.14);border:1px solid rgba(239,68,68,.32);border-radius:10px;padding:10px 12px;color:#fecaca;margin-bottom:12px}
    input,button{width:100%;padding:11px 12px;border-radius:10px;border:1px solid var(--border);box-sizing:border-box}
    input{background:#0f1830;color:var(--text);margin-bottom:8px}
    input:focus{outline:none;box-shadow:none;border-color:var(--border)}
    button{cursor:pointer;color:#fff;border:none;background:linear-gradient(135deg,var(--accent),var(--accent2));font-weight:600}
    .row{display:flex;gap:8px;align-items:center}
    .row>*{flex:1}
    .tiny{font-size:12px;color:var(--muted)}
    .panel{background:#0f1830;border:1px solid var(--border);border-radius:10px;padding:12px;margin-top:10px}
    .logout{background:linear-gradient(135deg,#ef4444,#dc2626);max-width:180px}
    a{color:#86b7ff;text-decoration:none}
    a:hover{text-decoration:underline}
    .password-wrap{position:relative}
    .password-wrap input{padding-right:44px}
    .password-toggle{position:absolute;right:8px;top:42%;transform:translateY(-50%);width:auto;height:auto;border:none;border-radius:0;background:transparent;color:var(--text);padding:2px;margin:0;cursor:pointer}
    .repo-cta{margin-top:10px;background:#0f1830;border:1px solid var(--border);border-radius:10px;padding:10px}
    .repo-cta p{margin:0 0 6px 0;color:var(--text)}
    .clone-line{font-size:13px;color:#e5e7eb;background:rgba(15,23,42,.8);border:1px solid var(--border);border-radius:8px;padding:10px;overflow:auto;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
    .termux-cta{margin-top:10px;background:rgba(16,185,129,.12);border:1px solid rgba(16,185,129,.35);border-radius:10px;padding:10px}
    .termux-cta p{margin:0 0 6px 0;color:var(--text)}
    .termux-links{display:flex;flex-wrap:wrap;gap:8px}
    .platform-cta{margin-top:10px;background:rgba(124,58,237,.14);border:1px solid rgba(196,181,253,.35);border-radius:10px;padding:10px}
    .platform-cta p{margin:0 0 6px 0;color:var(--text)}
    .platform-cmd{font-size:13px;color:#e5e7eb;background:rgba(15,23,42,.8);border:1px solid var(--border);border-radius:8px;padding:10px;overflow:auto;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
    .code-wrap{display:flex;gap:8px;align-items:stretch}
    .code-wrap pre{flex:1 1 auto;margin:0}
    .copy-btn{width:auto;padding:8px 12px;border-radius:8px;border:1px solid var(--border);background:transparent;color:var(--text);margin:0;box-shadow:none}
    .tutorial-cta{margin-top:10px;background:rgba(14,165,233,.12);border:1px solid rgba(103,232,249,.35);border-radius:10px;padding:10px}
    .tutorial-cta p{margin:0 0 6px 0;color:var(--text)}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Ginto Mobile Runtime</h1>
      <p>Android/iOS shell mode (PHP + SQLite). Desktop remains on Python runtime.</p>
      <p class="tiny">Platform detected: <?= htmlspecialchars($platform, ENT_QUOTES, 'UTF-8') ?></p>

      <?php if ($error !== ''): ?>
        <div class="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
      <?php endif; ?>

      <?php if ($user === null): ?>
        <?php if ($mode === 'setup'): ?>
          <form method="post">
            <input type="hidden" name="action" value="setup" />
            <input name="username" placeholder="Username" required minlength="3" />
            <div class="password-wrap">
              <input id="password" type="password" name="password" placeholder="Password" required minlength="8" />
              <button class="password-toggle" type="button" data-target="password" aria-label="Show password">👁</button>
            </div>
            <button type="submit">Create Login</button>
          </form>
        <?php else: ?>
          <form method="post">
            <input type="hidden" name="action" value="login" />
            <input name="username" placeholder="Username" required minlength="3" />
            <div class="password-wrap">
              <input id="password" type="password" name="password" placeholder="Password" required />
              <button class="password-toggle" type="button" data-target="password" aria-label="Show password">👁</button>
            </div>
            <button type="submit">Login</button>
          </form>
        <?php endif; ?>
        <section class="repo-cta">
          <p><a href="https://github.com/oliverbob/gntl" target="_blank" rel="noopener noreferrer">1) Star us on GitHub</a></p>
          <p><a href="https://github.com/oliverbob/gntl" target="_blank" rel="noopener noreferrer">2) Clone the Repo</a></p>
          <div class="code-wrap">
            <pre class="clone-line"><code id="repoCloneCmd">git clone https://github.com/oliverbob/gntl</code></pre>
            <button class="copy-btn" type="button" data-copy-target="repoCloneCmd">Copy</button>
          </div>
        </section>
        <section class="tutorial-cta">
          <p>Need full setup steps? Open the cross-platform tutorial.</p>
          <a href="/tutorial">Open Tutorial</a>
        </section>
        <section id="termuxCta" class="termux-cta">
          <p id="termuxDetectMeta">Detecting Android version and matching Termux package...</p>
          <div class="termux-links">
            <a id="termuxAutoLink" href="https://github.com/termux/termux-app/releases/latest" target="_blank" rel="noopener noreferrer">Download</a>
          </div>
        </section>
        <section id="platformCta" class="platform-cta">
          <p id="platformMeta">Detecting your device environment for Ginto Tunnel setup...</p>
          <a id="platformLink" href="https://github.com/oliverbob/gntl" target="_blank" rel="noopener noreferrer">Open Ginto Tunnel Repository</a>
          <div class="code-wrap">
            <pre class="platform-cmd"><code id="platformCmd">git clone https://github.com/oliverbob/gntl</code></pre>
            <button class="copy-btn" type="button" data-copy-target="platformCmd">Copy</button>
          </div>
        </section>
      <?php else: ?>
        <div class="panel">
          <strong>Welcome, <?= htmlspecialchars($user, ENT_QUOTES, 'UTF-8') ?></strong>
          <p>This is the lightweight mobile control surface. Full desktop feature parity is being migrated.</p>
          <ul>
            <li>Auth persisted in SQLite: <code>configs/webadmin_mobile.sqlite3</code></li>
            <li>Web runtime: PHP built-in server (or Caddy reverse proxy when available)</li>
            <li>Desktop Python runtime remains unchanged on non-mobile shells</li>
          </ul>
          <a href="https://github.com/termux/termux-app/releases" target="_blank" rel="noopener noreferrer">Download Termux</a>
        </div>
        <form method="post" style="margin-top:12px">
          <input type="hidden" name="action" value="logout" />
          <button class="logout" type="submit">Logout</button>
        </form>
      <?php endif; ?>
    </div>
  </div>
  <script>
    (function () {
      function initPasswordToggles() {
        document.querySelectorAll('.password-toggle').forEach((toggle) => {
          toggle.addEventListener('click', () => {
            const target = toggle.getAttribute('data-target');
            const input = target ? document.getElementById(target) : null;
            if (!input) return;
            const masked = input.type === 'password';
            input.type = masked ? 'text' : 'password';
            toggle.setAttribute('aria-label', masked ? 'Hide password' : 'Show password');
          });
        });
      }

      function initCopyButtons() {
        document.querySelectorAll('.copy-btn').forEach((btn) => {
          btn.addEventListener('click', async () => {
            const target = btn.getAttribute('data-copy-target');
            const code = target ? document.getElementById(target) : null;
            const text = code ? (code.textContent || '').trim() : '';
            if (!text) return;
            try {
              await navigator.clipboard.writeText(text);
              const prev = btn.textContent;
              btn.textContent = 'Copied';
              setTimeout(() => { btn.textContent = prev || 'Copy'; }, 1200);
            } catch (_err) {
            }
          });
        });
      }

      function isAndroidDevice() {
        const ua = (navigator.userAgent || '').toLowerCase();
        const uaData = navigator.userAgentData;
        if (uaData && Array.isArray(uaData.platforms)) {
          if (uaData.platforms.some((p) => String(p || '').toLowerCase().includes('android'))) return true;
        }
        if (uaData && typeof uaData.platform === 'string' && uaData.platform.toLowerCase().includes('android')) return true;
        return ua.includes('android');
      }

      function detectPlatformFamily() {
        const ua = (navigator.userAgent || '').toLowerCase();
        const platform = ((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '').toLowerCase();
        if (ua.includes('android') || platform.includes('android')) return 'android';
        if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ipod')) return 'ios';
        if (platform.includes('win') || ua.includes('windows')) return 'windows';
        if (platform.includes('mac') || ua.includes('mac os')) return 'macos';
        if (platform.includes('linux') || ua.includes('linux')) return 'linux';
        return 'unknown';
      }

      function parseAndroidMajor(uaValue) {
        const match = String(uaValue || '').match(/Android\s+([0-9]+)(?:\.([0-9]+))?/i);
        if (!match) return null;
        const major = parseInt(match[1], 10);
        return Number.isFinite(major) ? major : null;
      }

      function androidMajorToApi(major) {
        const mapping = {16:36,15:35,14:34,13:33,12:31,11:30,10:29,9:28,8:26,7:24,6:23,5:21};
        return mapping[major] || null;
      }

      function detectArchitecture() {
        const ua = (navigator.userAgent || '').toLowerCase();
        if (ua.includes('arm64') || ua.includes('aarch64')) return 'arm64-v8a';
        if (ua.includes('armeabi') || ua.includes('armv7')) return 'armeabi-v7a';
        if (ua.includes('x86_64') || ua.includes('amd64')) return 'x86_64';
        if (ua.includes(' x86') || ua.includes('i686')) return 'x86';
        return 'universal';
      }

      function pickBestAsset(assets, arch, apiLevel) {
        const apks = (assets || []).filter((asset) => String(asset.name || '').toLowerCase().endsWith('.apk'));
        if (!apks.length) return null;
        let best = null;
        let bestScore = -1;
        for (const asset of apks) {
          const name = String(asset.name || '').toLowerCase();
          const apiMatch = name.match(/api\s*([0-9]+)/i);
          if (apiMatch && apiLevel) {
            const requiredApi = parseInt(apiMatch[1], 10);
            if (Number.isFinite(requiredApi) && requiredApi > apiLevel) continue;
          }
          let score = 0;
          if (name.includes(arch)) score += 100;
          if (name.includes('universal')) score += 80;
          if (name.includes('github')) score += 20;
          if (!name.includes('fdroid')) score += 10;
          if (score > bestScore) {
            best = asset;
            bestScore = score;
          }
        }
        return best || apks[0];
      }

      async function getAndroidMajorFromUAData() {
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

      async function initTermuxDownloadCta() {
        const cta = document.getElementById('termuxCta');
        const termuxMeta = document.getElementById('termuxDetectMeta');
        const termuxAutoLink = document.getElementById('termuxAutoLink');
        if (!cta || !termuxMeta || !termuxAutoLink) return;

        const platform = detectPlatformFamily();
        if (platform === 'ios') {
          termuxMeta.textContent = 'Use iSH from link above for iOS.';
          termuxAutoLink.textContent = 'Download';
          termuxAutoLink.href = 'https://ish.app';
          return;
        }
        if (platform !== 'android') {
          cta.style.display = 'none';
          return;
        }

        if (!isAndroidDevice()) {
          termuxMeta.textContent = 'Android not detected in this browser. Open this page on Android to enable autodetected Termux download.';
          termuxAutoLink.textContent = 'Download';
          termuxAutoLink.href = 'https://github.com/termux/termux-app/releases/latest';
          return;
        }

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
            const versionText = androidMajor ? ('Android ' + androidMajor) : 'Android';
            const apiText = apiLevel ? ('API ' + apiLevel) : 'API unknown';
            termuxAutoLink.href = bestAsset.browser_download_url;
            termuxAutoLink.textContent = 'Download';
            termuxMeta.textContent = 'Detected ' + versionText + ' (' + apiText + ') on ' + arch + '. Suggested package: ' + bestAsset.name;
            return;
          }
        } catch (_err) {
        }

        termuxAutoLink.href = 'https://github.com/termux/termux-app/releases/latest';
        termuxAutoLink.textContent = 'Download';
        termuxMeta.textContent = 'Detected Android device. Could not fetch exact package details, so latest Termux release is linked.';
      }

      function initPlatformRecommendations() {
        const meta = document.getElementById('platformMeta');
        const link = document.getElementById('platformLink');
        const cmd = document.getElementById('platformCmd');
        const cta = document.getElementById('platformCta');
        if (!meta || !link || !cmd || !cta) return;

        const platform = detectPlatformFamily();
        if (platform === 'android') {
          cta.style.display = 'none';
          return;
        }
        if (platform === 'ios') {
          cta.style.display = 'none';
          return;
        }
        if (platform === 'windows') {
          meta.textContent = 'Windows desktop detected. Install Git + Python, then clone Ginto Tunnel.';
          link.textContent = 'Open Ginto Tunnel Repository';
          link.href = 'https://github.com/oliverbob/gntl';
          cmd.textContent = 'git clone https://github.com/oliverbob/gntl';
          return;
        }
        if (platform === 'macos') {
          meta.textContent = 'macOS desktop detected. Install git/python (or brew), then clone Ginto Tunnel.';
          link.textContent = 'Open Ginto Tunnel Repository';
          link.href = 'https://github.com/oliverbob/gntl';
          cmd.textContent = 'git clone https://github.com/oliverbob/gntl';
          return;
        }
        if (platform === 'linux') {
          meta.textContent = 'Linux desktop detected. Clone Ginto Tunnel and run setup in your environment.';
          link.textContent = 'Open Ginto Tunnel Repository';
          link.href = 'https://github.com/oliverbob/gntl';
          cmd.textContent = 'git clone https://github.com/oliverbob/gntl';
          return;
        }
        meta.textContent = 'Could not identify your platform. Open the repository and follow setup instructions for your environment.';
        link.textContent = 'Open Ginto Tunnel Repository';
        link.href = 'https://github.com/oliverbob/gntl';
        cmd.textContent = 'git clone https://github.com/oliverbob/gntl';
      }

      initPasswordToggles();
      initCopyButtons();
      initTermuxDownloadCta();
      initPlatformRecommendations();
    })();
  </script>
</body>
</html>
