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
        $confirm = (string)($_POST['confirm'] ?? '');

        if (!require_length($username, 3)) {
            $error = 'Username must be at least 3 characters.';
        } elseif (strlen($password) < 8) {
            $error = 'Password must be at least 8 characters.';
        } elseif ($password !== $confirm) {
            $error = 'Password confirmation does not match.';
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
    button{cursor:pointer;color:#fff;border:none;background:linear-gradient(135deg,var(--accent),var(--accent2));font-weight:600}
    .row{display:flex;gap:8px;align-items:center}
    .row>*{flex:1}
    .tiny{font-size:12px;color:var(--muted)}
    .panel{background:#0f1830;border:1px solid var(--border);border-radius:10px;padding:12px;margin-top:10px}
    .logout{background:linear-gradient(135deg,#ef4444,#dc2626);max-width:180px}
    a{color:#86b7ff;text-decoration:none}
    a:hover{text-decoration:underline}
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
            <input type="password" name="password" placeholder="Password" required minlength="8" />
            <input type="password" name="confirm" placeholder="Confirm Password" required minlength="8" />
            <button type="submit">Create Login</button>
          </form>
        <?php else: ?>
          <form method="post">
            <input type="hidden" name="action" value="login" />
            <input name="username" placeholder="Username" required minlength="3" />
            <input type="password" name="password" placeholder="Password" required />
            <button type="submit">Login</button>
          </form>
        <?php endif; ?>
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
</body>
</html>
