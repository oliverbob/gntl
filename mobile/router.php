<?php
$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$file = __DIR__ . $uri;
if ($uri !== '/' && is_file($file)) {
    return false;
}

$root = dirname(__DIR__);
if (str_starts_with($uri, '/static/')) {
    $staticFile = $root . $uri;
    if (is_file($staticFile)) {
        $ext = strtolower(pathinfo($staticFile, PATHINFO_EXTENSION));
        $mime = match ($ext) {
            'js' => 'application/javascript; charset=utf-8',
            'css' => 'text/css; charset=utf-8',
            'png' => 'image/png',
            'jpg', 'jpeg' => 'image/jpeg',
            'svg' => 'image/svg+xml',
            'ico' => 'image/x-icon',
            default => 'application/octet-stream',
        };
        header('Content-Type: ' . $mime);
        readfile($staticFile);
        exit;
    }
}

require __DIR__ . '/index.php';
