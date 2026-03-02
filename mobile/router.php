<?php
$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$file = __DIR__ . $uri;
if ($uri !== '/' && is_file($file)) {
    return false;
}

$root = dirname(__DIR__);

$serveStaticFile = static function (string $path): void {
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    $mime = match ($ext) {
        'js', 'mjs' => 'application/javascript; charset=utf-8',
        'css' => 'text/css; charset=utf-8',
        'html' => 'text/html; charset=utf-8',
        'json', 'map', 'webmanifest' => 'application/json; charset=utf-8',
        'png' => 'image/png',
        'jpg', 'jpeg' => 'image/jpeg',
        'svg' => 'image/svg+xml',
        'ico' => 'image/x-icon',
        'txt' => 'text/plain; charset=utf-8',
        'woff' => 'font/woff',
        'woff2' => 'font/woff2',
        'ttf' => 'font/ttf',
        'otf' => 'font/otf',
        'wasm' => 'application/wasm',
        default => 'application/octet-stream',
    };
    header('Content-Type: ' . $mime);
    readfile($path);
    exit;
};

$frontendBuildDir = $root . '/frontend/build';
if ($uri !== '/' && is_dir($frontendBuildDir)) {
    $normalized = ltrim($uri, '/');
    if ($normalized !== '' && strpos($normalized, '..') === false) {
        $candidate = $frontendBuildDir . '/' . $normalized;
        if (is_file($candidate)) {
            $serveStaticFile($candidate);
        }
    }
}

if (str_starts_with($uri, '/static/')) {
    $staticCandidates = [
        $root . '/backend/src/gntl' . $uri,
        $root . $uri,
    ];
    $staticFile = '';
    foreach ($staticCandidates as $candidate) {
        if (is_file($candidate)) {
            $staticFile = $candidate;
            break;
        }
    }
    if (is_file($staticFile)) {
        $serveStaticFile($staticFile);
    }
}

require __DIR__ . '/index.php';
