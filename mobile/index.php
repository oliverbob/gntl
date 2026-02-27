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
    .clone-line{font-size:13px;color:var(--muted)}
    .termux-cta{margin-top:10px;background:rgba(16,185,129,.12);border:1px solid rgba(16,185,129,.35);border-radius:10px;padding:10px}
    .termux-cta p{margin:0 0 6px 0;color:var(--text)}
    .termux-links{display:flex;flex-wrap:wrap;gap:8px}
    .platform-cta{margin-top:10px;background:rgba(124,58,237,.14);border:1px solid rgba(196,181,253,.35);border-radius:10px;padding:10px}
    .platform-cta p{margin:0 0 6px 0;color:var(--text)}
    .platform-cmd{font-size:13px;color:var(--muted)}
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
          <p class="clone-line">To clone: git clone https://github.com/oliverbob/gntl</p>
        </section>
        <section id="termuxCta" class="termux-cta">
          <p id="termuxDetectMeta">Detecting Android version and matching Termux package...</p>
          <div class="termux-links">
            <a id="termuxReleaseLink" href="https://github.com/termux/termux-app/releases" target="_blank" rel="noopener noreferrer">Download from GitHub Releases</a>
            <a id="termuxAutoLink" href="https://github.com/termux/termux-app/releases/latest" target="_blank" rel="noopener noreferrer">Download Autodetected</a>
          </div>
        </section>
        <section id="platformCta" class="platform-cta">
          <p id="platformMeta">Detecting your device environment for Ginto Tunnel setup...</p>
          <a id="platformLink" href="https://github.com/oliverbob/gntl" target="_blank" rel="noopener noreferrer">Open Ginto Tunnel Repository</a>
          <p id="platformCmd" class="platform-cmd">git clone https://github.com/oliverbob/gntl</p>
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
        const termuxMeta = document.getElementById('termuxDetectMeta');
        const termuxAutoLink = document.getElementById('termuxAutoLink');
        if (!termuxMeta || !termuxAutoLink) return;

        if (!isAndroidDevice()) {
          termuxMeta.textContent = 'Android not detected in this browser. Open this page on Android to enable autodetected Termux download.';
          termuxAutoLink.textContent = 'Download Autodetected (Open on Android)';
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
            termuxAutoLink.textContent = 'Download Autodetected (' + versionText + ' / ' + apiText + ')';
            termuxMeta.textContent = 'Detected ' + versionText + ' (' + apiText + ') on ' + arch + '. Suggested package: ' + bestAsset.name;
            return;
          }
        } catch (_err) {
        }

        termuxAutoLink.href = 'https://github.com/termux/termux-app/releases/latest';
        termuxAutoLink.textContent = 'Download Autodetected (Latest)';
        termuxMeta.textContent = 'Detected Android device. Could not fetch exact package details, so latest Termux release is linked.';
      }

      function initPlatformRecommendations() {
        const meta = document.getElementById('platformMeta');
        const link = document.getElementById('platformLink');
        const cmd = document.getElementById('platformCmd');
        if (!meta || !link || !cmd) return;

        const platform = detectPlatformFamily();
        if (platform === 'android') {
          meta.textContent = 'Android detected. Use Termux from the links above, then clone and run Ginto Tunnel.';
          link.textContent = 'Download Termux (Android)';
          link.href = 'https://github.com/termux/termux-app/releases';
          cmd.textContent = 'pkg install git && git clone https://github.com/oliverbob/gntl';
          return;
        }
        if (platform === 'ios') {
          meta.textContent = 'iOS detected. Use iSH shell (Alpine), then clone and run Ginto Tunnel from there.';
          link.textContent = 'Open Ginto Tunnel Repository';
          link.href = 'https://github.com/oliverbob/gntl';
          cmd.textContent = 'apk add git php84 && git clone https://github.com/oliverbob/gntl';
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
      initTermuxDownloadCta();
      initPlatformRecommendations();
    })();
  </script>
</body>
</html>
