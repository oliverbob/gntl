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

function json_response(array $data, int $status = 200): void {
  http_response_code($status);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode($data, JSON_UNESCAPED_SLASHES);
  exit;
}

function read_json_input(): array {
  $raw = file_get_contents('php://input');
  if (!is_string($raw) || trim($raw) === '') {
    return [];
  }
  $decoded = json_decode($raw, true);
  return is_array($decoded) ? $decoded : [];
}

function state_file_path(): string {
  return app_root() . '/configs/instances_state.json';
}

function frpc_bin_path(): string {
  return app_root() . '/bin/frpc';
}

function logs_dir_path(): string {
  $dir = app_root() . '/configs/logs';
  if (!is_dir($dir)) {
    mkdir($dir, 0775, true);
  }
  return $dir;
}

function safe_instance_id(string $id): string {
  $safe = preg_replace('/[^A-Za-z0-9._-]/', '_', $id);
  return is_string($safe) && $safe !== '' ? $safe : 'inst';
}

function pid_file_path(string $id): string {
  return app_root() . '/configs/.gntl-frpc-' . safe_instance_id($id) . '.pid';
}

function log_file_path(string $id): string {
  return logs_dir_path() . '/frpc-' . safe_instance_id($id) . '.log';
}

function load_state(): array {
  $path = state_file_path();
  if (!is_file($path)) {
    return [];
  }
  $raw = file_get_contents($path);
  if (!is_string($raw) || trim($raw) === '') {
    return [];
  }
  $decoded = json_decode($raw, true);
  return is_array($decoded) ? $decoded : [];
}

function save_state(array $state): void {
  $path = state_file_path();
  $dir = dirname($path);
  if (!is_dir($dir)) {
    mkdir($dir, 0775, true);
  }
  file_put_contents($path, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function process_running(int $pid): bool {
  if ($pid <= 0) {
    return false;
  }
  if (function_exists('posix_kill')) {
    return @posix_kill($pid, 0);
  }
  exec('kill -0 ' . (int)$pid . ' >/dev/null 2>&1', $_out, $code);
  return $code === 0;
}

function read_pid(string $id): ?int {
  $path = pid_file_path($id);
  if (!is_file($path)) {
    return null;
  }
  $raw = trim((string)file_get_contents($path));
  if ($raw === '' || !ctype_digit($raw)) {
    @unlink($path);
    return null;
  }
  $pid = (int)$raw;
  if (!process_running($pid)) {
    @unlink($path);
    return null;
  }
  return $pid;
}

function stop_instance_process(string $id): bool {
  $pid = read_pid($id);
  $pidPath = pid_file_path($id);
  if ($pid === null) {
    @unlink($pidPath);
    return true;
  }

  if (function_exists('posix_kill')) {
    @posix_kill($pid, SIGTERM);
    usleep(150000);
    if (process_running($pid)) {
      @posix_kill($pid, SIGKILL);
    }
  } else {
    exec('kill ' . (int)$pid . ' >/dev/null 2>&1');
    usleep(150000);
    if (process_running($pid)) {
      exec('kill -9 ' . (int)$pid . ' >/dev/null 2>&1');
    }
  }

  @unlink($pidPath);
  return true;
}

function render_frpc_config_text(string $serverAddr, int $serverPort, string $authToken, string $proxyName, int $localPort, string $subdomain, string $protocol): string {
  $proto = strtolower(trim($protocol));
  if ($proto !== 'http' && $proto !== 'https') {
    $proto = 'http';
  }
  $hostRewrite = $proto === 'http' ? "hostHeaderRewrite = \"127.0.0.1\"\n" : '';
  $domain = ($subdomain !== '' && $serverAddr !== '') ? ($subdomain . '.' . $serverAddr) : $subdomain;
  $routingLine = $proto === 'https'
    ? "customDomains = [\"{$domain}\"]\n"
    : "subdomain = \"{$subdomain}\"\n";
  return "serverAddr = \"{$serverAddr}\"\n"
    . "serverPort = {$serverPort}\n\n"
    . "[auth]\n"
    . "method = \"token\"\n"
    . "token = \"{$authToken}\"\n\n"
    . "[transport]\n"
    . "poolCount = 3\n\n"
    . "[transport.tls]\n"
    . "enable = true\n"
    . "disableCustomTLSFirstByte = true\n\n"
    . "[log]\n"
    . "to = \"/tmp/frpc-tunnel.log\"\n"
    . "level = \"info\"\n"
    . "maxDays = 3\n\n"
    . "[[proxies]]\n"
    . "name = \"{$proxyName}\"\n"
    . "type = \"{$proto}\"\n"
    . "localIP = \"127.0.0.1\"\n"
    . "localPort = {$localPort}\n"
    . $routingLine
    . $hostRewrite;
}

function start_instance_process(string $id, string $configPath): bool {
  $bin = frpc_bin_path();
  if (!is_file($bin) || !is_executable($bin) || !is_file($configPath)) {
    return false;
  }

  stop_instance_process($id);
  $logFile = log_file_path($id);
  $pidFile = pid_file_path($id);
  $cmd = escapeshellarg($bin) . ' -c ' . escapeshellarg($configPath)
    . ' >> ' . escapeshellarg($logFile) . ' 2>&1 & echo $!';
  $pidRaw = trim((string)shell_exec($cmd));
  if ($pidRaw === '' || !ctype_digit($pidRaw)) {
    return false;
  }
  $pid = (int)$pidRaw;
  if ($pid <= 0) {
    return false;
  }
  file_put_contents($pidFile, (string)$pid);
  return process_running($pid);
}

function cleanup_deleted_instances(array $state): array {
  $activeSafe = [];
  foreach ($state as $id => $_entry) {
    $activeSafe[safe_instance_id((string)$id)] = true;
  }

  $killed = 0;
  $removedPidFiles = 0;
  $removedLogs = 0;

  foreach (glob(app_root() . '/configs/.gntl-frpc-*.pid') ?: [] as $pidPath) {
    $base = basename($pidPath);
    $safe = preg_replace('/^\.gntl-frpc-(.+)\.pid$/', '$1', $base);
    if (!is_string($safe) || $safe === '' || isset($activeSafe[$safe])) {
      continue;
    }
    $raw = trim((string)@file_get_contents($pidPath));
    if ($raw !== '' && ctype_digit($raw)) {
      $pid = (int)$raw;
      if ($pid > 0 && process_running($pid)) {
        if (function_exists('posix_kill')) {
          @posix_kill($pid, SIGTERM);
          usleep(150000);
          if (process_running($pid)) {
            @posix_kill($pid, SIGKILL);
          }
        } else {
          exec('kill ' . (int)$pid . ' >/dev/null 2>&1');
          usleep(150000);
          if (process_running($pid)) {
            exec('kill -9 ' . (int)$pid . ' >/dev/null 2>&1');
          }
        }
        $killed++;
      }
    }
    @unlink($pidPath);
    $removedPidFiles++;
  }

  foreach (glob(logs_dir_path() . '/frpc-*.log') ?: [] as $logPath) {
    $base = basename($logPath);
    $safe = preg_replace('/^frpc-(.+)\.log$/', '$1', $base);
    if (!is_string($safe) || $safe === '' || isset($activeSafe[$safe])) {
      continue;
    }
    @unlink($logPath);
    $removedLogs++;
  }

  return [
    'killedPids' => $killed,
    'removedPidFiles' => $removedPidFiles,
    'removedLogs' => $removedLogs,
  ];
}

function tail_lines_from_file(string $path, int $maxLines): array {
  if (!is_file($path) || $maxLines <= 0) {
    return [];
  }
  $lines = @file($path, FILE_IGNORE_NEW_LINES);
  if (!is_array($lines)) {
    return [];
  }
  if (count($lines) <= $maxLines) {
    return $lines;
  }
  return array_slice($lines, -$maxLines);
}

function ensure_mobile_auth(): string {
  $user = current_user();
  if ($user === null) {
    json_response(['detail' => 'authentication required'], 401);
  }
  return $user;
}

function exec_admin_command(string $command): array {
  $command = trim($command);
  if ($command === '') {
    return ['ok' => false, 'exitCode' => 400, 'output' => 'command is required'];
  }
  if (strlen($command) > 2000) {
    return ['ok' => false, 'exitCode' => 400, 'output' => 'command is too long'];
  }

  $cwd = app_root();
  $timeoutSeconds = 12;
  $wrapped = 'sh -lc ' . escapeshellarg($command);
  $runner = 'timeout ' . (int)$timeoutSeconds . 's ' . $wrapped;
  $hasTimeout = trim((string)shell_exec('command -v timeout 2>/dev/null')) !== '';
  if (!$hasTimeout) {
    $runner = $wrapped;
  }

  $descriptors = [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
  ];
  $proc = @proc_open($runner, $descriptors, $pipes, $cwd, [
    'TERM' => getenv('TERM') ?: 'xterm-256color',
  ]);
  if (!is_resource($proc)) {
    return ['ok' => false, 'exitCode' => 500, 'output' => 'failed to start process'];
  }

  fclose($pipes[0]);
  stream_set_blocking($pipes[1], false);
  stream_set_blocking($pipes[2], false);

  $stdout = '';
  $stderr = '';
  $deadline = microtime(true) + $timeoutSeconds + 1;
  while (microtime(true) < $deadline) {
    $status = proc_get_status($proc);
    $stdout .= (string)stream_get_contents($pipes[1]);
    $stderr .= (string)stream_get_contents($pipes[2]);
    if (!$status['running']) {
      break;
    }
    usleep(120000);
  }

  $status = proc_get_status($proc);
  $timedOut = false;
  if ($status['running']) {
    $timedOut = true;
    proc_terminate($proc, 9);
  }

  $stdout .= (string)stream_get_contents($pipes[1]);
  $stderr .= (string)stream_get_contents($pipes[2]);
  fclose($pipes[1]);
  fclose($pipes[2]);
  $exitCode = proc_close($proc);
  if ($timedOut) {
    $exitCode = 124;
  }

  $output = $stdout . $stderr;
  if ($timedOut) {
    $output .= "\n[terminated: command timed out]\n";
  }
  $truncated = false;
  if (strlen($output) > 20000) {
    $output = substr($output, 0, 20000) . "\n[truncated]\n";
    $truncated = true;
  }

  return [
    'ok' => $exitCode === 0,
    'exitCode' => $exitCode,
    'output' => $output,
    'timedOut' => $timedOut,
    'truncated' => $truncated,
    'cwd' => $cwd,
  ];
}

function route_mobile_api(string $uriPath, string $method): void {
  if ($uriPath === '/api/auth/setup-status' && $method === 'GET') {
    json_response([
      'hasPassword' => has_password(),
      'username' => current_user(),
      'authenticated' => current_user() !== null,
    ]);
  }

  if ($uriPath === '/api/auth/logout' && $method === 'POST') {
    unset($_SESSION[SESSION_KEY]);
    json_response(['ok' => true]);
  }

  $username = ensure_mobile_auth();

  if ($uriPath === '/api/admin/terminal/exec' && $method === 'POST') {
    $body = read_json_input();
    $command = (string)($body['command'] ?? '');
    $result = exec_admin_command($command);
    $result['command'] = trim($command);
    json_response($result, isset($result['exitCode']) && (int)$result['exitCode'] === 400 ? 400 : 200);
  }

  if ($uriPath === '/api/instances' && $method === 'GET') {
    $state = load_state();
    $out = [];
    foreach ($state as $id => $entry) {
      if (!is_array($entry)) {
        continue;
      }
      $meta = isset($entry['metadata']) && is_array($entry['metadata']) ? $entry['metadata'] : [];
      $owner = (string)($meta['owner'] ?? '');
      if ($owner !== '' && $owner !== $username) {
        continue;
      }
      $pid = read_pid((string)$id);
      $out[(string)$id] = [
        'status' => $pid !== null ? 'running' : 'stopped',
        'config' => (string)($entry['config_path'] ?? ''),
        'pid' => $pid,
        'uptime' => null,
        'proxyName' => $meta['proxyName'] ?? null,
        'subdomain' => $meta['subdomain'] ?? null,
        'serverAddr' => $meta['serverAddr'] ?? null,
        'serverPort' => $meta['serverPort'] ?? null,
        'localPort' => $meta['localPort'] ?? null,
        'enabled' => (bool)($meta['enabled'] ?? true),
        'groupId' => $meta['groupId'] ?? null,
        'owner' => $owner !== '' ? $owner : $username,
        'protocol' => $meta['protocol'] ?? null,
      ];
    }
    json_response($out);
  }

  if ($uriPath === '/api/instances/cleanup-deleted' && $method === 'POST') {
    $state = load_state();
    $result = cleanup_deleted_instances($state);
    json_response(['ok' => true, 'result' => $result]);
  }

  if ($uriPath === '/api/instances' && $method === 'POST') {
    $body = read_json_input();
    $groupId = trim((string)($body['id'] ?? ''));
    $proxyName = trim((string)($body['proxyName'] ?? 'proxy'));
    $subdomain = trim((string)($body['subdomain'] ?? 'tunnel'));
    $serverAddr = trim((string)($body['serverAddr'] ?? 'ginto.ai'));
    $localHttpPort = (int)($body['localHttpPort'] ?? ($body['localPort'] ?? 80));
    $localHttpsPort = (int)($body['localHttpsPort'] ?? $localHttpPort);
    $serverPort = 7000;
    $authToken = '0868d7a0943085871e506e79c8589bd1d80fbd9852b441165237deea6e16955a';

    if ($groupId === '') {
      json_response(['detail' => 'id required'], 400);
    }
    if ($localHttpPort <= 0 || $localHttpPort > 65535) {
      $localHttpPort = 80;
    }
    if ($localHttpsPort <= 0 || $localHttpsPort > 65535) {
      $localHttpsPort = $localHttpPort;
    }

    $state = load_state();
    $pairIds = [$groupId . '-http', $groupId . '-https'];
    foreach ($pairIds as $pairId) {
      if (array_key_exists($pairId, $state)) {
        json_response(['detail' => 'instance already exists: ' . $pairId], 409);
      }
    }

    $cfgDir = app_root() . '/configs';
    if (!is_dir($cfgDir)) {
      mkdir($cfgDir, 0775, true);
    }

    $created = [];
    foreach (['http', 'https'] as $protocol) {
      $instanceId = $groupId . '-' . $protocol;
      $proxyByProtocol = $proxyName . '-' . $protocol;
      $protocolLocalPort = $protocol === 'https' ? $localHttpsPort : $localHttpPort;
      $cfgPath = $cfgDir . '/' . $instanceId . '.toml';
      $cfg = render_frpc_config_text($serverAddr, $serverPort, $authToken, $proxyByProtocol, $protocolLocalPort, $subdomain, $protocol);
      file_put_contents($cfgPath, $cfg);

      $state[$instanceId] = [
        'config_path' => $cfgPath,
        'metadata' => [
          'proxyName' => $proxyByProtocol,
          'subdomain' => $subdomain,
          'serverAddr' => $serverAddr,
          'serverPort' => $serverPort,
          'localPort' => $protocolLocalPort,
          'localHttpPort' => $localHttpPort,
          'localHttpsPort' => $localHttpsPort,
          'groupId' => $groupId,
          'owner' => $username,
          'protocol' => $protocol,
          'enabled' => true,
        ],
      ];

      $autoStarted = start_instance_process($instanceId, $cfgPath);
      $autoStartError = $autoStarted ? null : 'failed to auto-start instance';

      $created[] = [
        'id' => $instanceId,
        'groupId' => $groupId,
        'owner' => $username,
        'protocol' => $protocol,
        'configPath' => $cfgPath,
        'autoStarted' => $autoStarted,
        'autoStartError' => $autoStartError,
      ];
    }
    save_state($state);
    json_response(['ok' => true, 'groupId' => $groupId, 'created' => $created]);
  }

  if (preg_match('#^/api/instances/([^/]+)/logs$#', $uriPath, $m) && $method === 'GET') {
    $id = $m[1];
    $state = load_state();
    if (!isset($state[$id])) {
      json_response(['detail' => 'not found'], 404);
    }
    $entry = $state[$id];
    $meta = isset($entry['metadata']) && is_array($entry['metadata']) ? $entry['metadata'] : [];
    $owner = (string)($meta['owner'] ?? '');
    if ($owner !== '' && $owner !== $username) {
      json_response(['detail' => 'forbidden'], 403);
    }
    $lines = isset($_GET['lines']) ? (int)$_GET['lines'] : 200;
    if ($lines <= 0) {
      $lines = 200;
    }
    if ($lines > 2000) {
      $lines = 2000;
    }
    json_response(['lines' => tail_lines_from_file(log_file_path($id), $lines)]);
  }

  if (preg_match('#^/api/instances/([^/]+)/(start|stop|restart)$#', $uriPath, $m) && $method === 'POST') {
    $id = $m[1];
    $action = $m[2];
    $state = load_state();
    if (!isset($state[$id])) {
      json_response(['detail' => 'not found'], 404);
    }
    $entry = $state[$id];
    $meta = isset($entry['metadata']) && is_array($entry['metadata']) ? $entry['metadata'] : [];
    $owner = (string)($meta['owner'] ?? '');
    if ($owner !== '' && $owner !== $username) {
      json_response(['detail' => 'forbidden'], 403);
    }
    $cfgPath = (string)($entry['config_path'] ?? '');

    if ($action === 'stop') {
      stop_instance_process($id);
      json_response(['ok' => true]);
    }

    if ($action === 'restart') {
      stop_instance_process($id);
    }

    $ok = start_instance_process($id, $cfgPath);
    json_response(['ok' => $ok], $ok ? 200 : 500);
  }

  if (preg_match('#^/api/instances/([^/]+)$#', $uriPath, $m) && $method === 'DELETE') {
    $id = $m[1];
    $state = load_state();
    if (!isset($state[$id])) {
      json_response(['detail' => 'not found'], 404);
    }
    $entry = $state[$id];
    $meta = isset($entry['metadata']) && is_array($entry['metadata']) ? $entry['metadata'] : [];
    $owner = (string)($meta['owner'] ?? '');
    if ($owner !== '' && $owner !== $username) {
      json_response(['detail' => 'forbidden'], 403);
    }
    stop_instance_process($id);
    $cfgPath = (string)($entry['config_path'] ?? '');
    if ($cfgPath !== '' && is_file($cfgPath)) {
      @unlink($cfgPath);
    }
    @unlink(log_file_path($id));
    unset($state[$id]);
    save_state($state);
    $cleanupResult = cleanup_deleted_instances($state);
    json_response(['ok' => true, 'cleanup' => $cleanupResult]);
  }

  json_response(['detail' => 'not found'], 404);
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
    .download-choice{margin:8px 0}
    .download-choice p{margin:0 0 6px 0}
    .download-choice a{margin-right:10px}
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
        <h3>iOS</h3>
        <div class="download-choice">
          <p>Your iOS version needs iSH shell, or you can Download it Manually from the same official source.</p>
          <a id="iosAutoDownload" href="https://ish.app" target="_blank" rel="noopener noreferrer">Your mobile version needs this version: iSH</a>
          <a id="iosManualDownload" href="https://ish.app" target="_blank" rel="noopener noreferrer">Download Manually</a>
        </div>
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
            if (bestAsset && bestAsset.browser_download_url){
              androidAuto.href = bestAsset.browser_download_url;
              androidAuto.textContent = 'Your mobile version needs this version: ' + bestAsset.name;
              androidNote.textContent = 'Your Android version needs ' + bestAsset.name + ', or you can Download it Manually from the same official source.';
            }
          } catch (_err) {
            androidAuto.href = 'https://github.com/termux/termux-app/releases/latest';
          }
        }
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
      initMobileDownloadChoices();
      showPlatform(detectPlatform());
    })();
  </script>
</body>
</html>
HTML;
}

function render_mobile_dashboard_page(): string {
  $templatePath = app_root() . '/templates/index.html';
  $html = @file_get_contents($templatePath);
  if (!is_string($html) || $html === '') {
    return '<!doctype html><html><body><h2>Dashboard template not found.</h2></body></html>';
  }

  $mobileFlags = "\n<script>window.GNTL_LOGIN_PATH='/' ;window.GNTL_DISABLE_WS=true;window.GNTL_DISABLE_CONSOLE=false;</script>\n";
  if (str_contains($html, '</body>')) {
    return str_replace('</body>', $mobileFlags . '</body>', $html);
  }
  return $html . $mobileFlags;
}

$uriPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
if (str_starts_with($uriPath, '/api/')) {
  route_mobile_api($uriPath, $method);
}
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
if ($user !== null) {
  echo render_mobile_dashboard_page();
  exit;
}
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
