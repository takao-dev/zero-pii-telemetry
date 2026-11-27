<?php
declare(strict_types=1);

header("Content-Security-Policy: frame-ancestors 'none'");
header('X-Frame-Options: DENY');

$requestPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$requestPath = is_string($requestPath) && $requestPath !== '' ? rawurldecode($requestPath) : '/';
$documentRoot = realpath(__DIR__);
$target = realpath(__DIR__ . $requestPath);

if ($requestPath === '/' || $requestPath === '/index.html') {
    readfile(__DIR__ . '/index.html');
    return true;
}

if ($documentRoot === false || $target === false || !str_starts_with($target, $documentRoot . DIRECTORY_SEPARATOR)) {
    http_response_code(404);
    return true;
}

if (is_file($target) && strtolower(pathinfo($target, PATHINFO_EXTENSION)) === 'php') {
    $publicPhpEndpoints = ['/collector.php', '/login.php', '/api/metrics.php', '/api/triage.php'];
    if (!in_array($requestPath, $publicPhpEndpoints, true)) {
        http_response_code(404);
        return true;
    }
    require $target;
    return true;
}

if (is_file($target)) {
    return false;
}

http_response_code(404);
return true;
