<?php
declare(strict_types=1);

/**
 * Fetch environment variable with OpenLiteSpeed LSPHP / FastCGI fallback.
 * Checks $_SERVER, $_ENV, and getenv() in order.
 */
function portal_env(string $name, ?string $default = null): ?string {
    $fallbackName = str_starts_with($name, 'TELEMETRY_')
        ? 'PORTAL_' . $name
        : (str_starts_with($name, 'PORTAL_TELEMETRY_') ? substr($name, 7) : null);

    foreach (array_filter([$name, $fallbackName]) as $key) {
        if (isset($_SERVER[$key]) && is_string($_SERVER[$key]) && $_SERVER[$key] !== '') {
            return $_SERVER[$key];
        }
        if (isset($_ENV[$key]) && is_string($_ENV[$key]) && $_ENV[$key] !== '') {
            return $_ENV[$key];
        }
        $val = getenv($key);
        if ($val !== false && $val !== '') {
            return $val;
        }
    }
    return $default;
}

/**
 * Resolve client IP with optional trusted proxy / Cloudflare support.
 * Falls back to REMOTE_ADDR unless client is behind a configured trusted proxy.
 */
function telemetry_client_ip(): string {
    $remote = (string)($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');
    $trustedProxies = portal_env('PORTAL_TRUSTED_PROXIES');
    if (!$trustedProxies) {
        return $remote;
    }
    $trustedList = array_map('trim', explode(',', $trustedProxies));
    if (!in_array($remote, $trustedList, true)) {
        return $remote;
    }

    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $cfIp = trim((string)$_SERVER['HTTP_CF_CONNECTING_IP']);
        if (filter_var($cfIp, FILTER_VALIDATE_IP)) {
            return $cfIp;
        }
    }

    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $forwarded = explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR']);
        $clientIp = trim($forwarded[0] ?? '');
        if (filter_var($clientIp, FILTER_VALIDATE_IP)) {
            return $clientIp;
        }
    }

    return $remote;
}

function telemetry_data_dir(): string {
    $configured = portal_env('PORTAL_TELEMETRY_DATA_DIR');
    if (!$configured || !preg_match('~^(?:/|[A-Za-z]:[\\\\/])~', $configured)) {
        throw new RuntimeException('Private telemetry directory must be configured');
    }
    if (!is_dir($configured) && !mkdir($configured, 0700, true) && !is_dir($configured)) {
        throw new RuntimeException('Private telemetry directory unavailable');
    }
    $path = realpath($configured);
    $documentRoot = $_SERVER['DOCUMENT_ROOT'] ?? '';
    $root = realpath($documentRoot !== '' ? $documentRoot : dirname(__DIR__));
    if (!$path || !$root) throw new RuntimeException('Unable to resolve storage boundary');
    $normalize = static function(string $p): string { return strtolower(str_replace('\\', '/', rtrim($p, '/\\'))); };
    if ($normalize($path) === $normalize($root) || strpos($normalize($path), $normalize($root) . '/') === 0) {
        throw new RuntimeException('Telemetry storage must be outside document root');
    }
    return $path;
}

function telemetry_open(string $path): PDO {
    $db = new PDO('sqlite:' . $path);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec('PRAGMA busy_timeout = 5000');
    return $db;
}

// Free-form message and stack content can contain arbitrary PII. Keep only finite classes.
function telemetry_message(string $message): string {
    foreach (['TypeError', 'ReferenceError', 'SyntaxError', 'RangeError', 'URIError', 'EvalError', 'UnhandledRejection'] as $type) {
        if (strpos($message, $type) !== false) return $type;
    }
    return 'ClientError';
}

function telemetry_url(string $url): string {
    if (in_array($url, ['inline', 'eval', 'wasm-eval', 'data', 'blob'], true)) return $url;
    $parts = parse_url($url);
    if (!is_array($parts) || !isset($parts['host'])) return '[redacted-url]';

    $configuredHosts = portal_env('TELEMETRY_ALLOWED_HOSTS') ?: portal_env('PORTAL_TELEMETRY_ALLOWED_HOSTS');
    if ($configuredHosts) {
        $hosts = array_map('trim', explode(',', strtolower($configuredHosts)));
    } else {
        $hosts = ['manage.takao.me', 'reports.takao.me', 'api.amga.jp', 'guardian.amga.jp', 'staff.amga.jp', 'docs.amga.jp',
            'api-staging.amga.jp', 'guardian-staging.amga.jp', 'staff-staging.amga.jp', 'docs-staging.amga.jp', 'localhost', '127.0.0.1'];
        if (isset($_SERVER['HTTP_HOST'])) {
            $currentHost = strtolower(explode(':', $_SERVER['HTTP_HOST'])[0]);
            if (!in_array($currentHost, $hosts, true)) $hosts[] = $currentHost;
        }
    }

    if (!in_array(strtolower($parts['host']), $hosts, true)) return '[redacted-url]';
    return 'https://' . strtolower($parts['host']) . '/[redacted]';
}

function telemetry_screen(string $screen): string {
    $configuredScreens = portal_env('TELEMETRY_ALLOWED_SCREENS') ?: portal_env('PORTAL_TELEMETRY_ALLOWED_SCREENS');
    if ($configuredScreens) {
        $allowed = array_map('trim', explode(',', strtolower($configuredScreens)));
    } else {
        $allowed = ['root','dashboard','login','account','organizations','devices','settings','logs','ip-bans','subsidy-rates','home','admin','portal'];
    }
    return in_array(strtolower($screen), $allowed, true) ? $screen : 'other';
}

function telemetry_service(string $service): string {
    $allowed = ['houkago-link', 'manage-portal', 'default', 'app', 'web', 'api', 'admin', 'unknown', 'other'];
    $configuredServices = portal_env('TELEMETRY_SERVICES') ?: portal_env('PORTAL_TELEMETRY_SERVICES');
    if ($configuredServices) {
        foreach (explode(',', $configuredServices) as $name) {
            $name = trim($name);
            if (preg_match('/^[a-zA-Z0-9_.-]{1,48}$/D', $name)) $allowed[] = $name;
        }
    }
    return in_array($service, $allowed, true) ? $service : 'other';
}

function telemetry_redact_rows(array $rows, bool $client): array {
    foreach ($rows as &$row) {
        $row['service'] = telemetry_service((string)($row['service'] ?? 'unknown'));
        if ($client) {
            $row['url'] = telemetry_url((string)($row['url'] ?? ''));
            $row['source'] = telemetry_url((string)($row['source'] ?? ''));
            $row['message'] = telemetry_message((string)($row['message'] ?? ''));
            $row['stack'] = '';
        } else {
            $row['raw_blocked_uri'] = telemetry_url((string)($row['raw_blocked_uri'] ?? ''));
            $row['screen'] = telemetry_screen((string)($row['screen'] ?? ''));
        }
    }
    return $rows;
}

function telemetry_limit(string $name, int $default, int $maximum): int {
    $value = portal_env($name);
    return $value !== null && ctype_digit($value) ? min($maximum, max(1, (int)$value)) : $default;
}

function telemetry_admit(string $dir): bool {
    $handle = fopen($dir . '/ingest-quota.json', 'c+');
    if (!$handle || !flock($handle, LOCK_EX)) throw new RuntimeException('Quota state unavailable');
    try {
        $raw = stream_get_contents($handle, 262145);
        if ($raw === false || strlen($raw) > 262144) throw new RuntimeException('Invalid quota state');
        $state = $raw === '' ? [] : json_decode($raw, true);
        if (!is_array($state)) throw new RuntimeException('Invalid quota state');
        $window = intdiv(time(), 60);
        if (($state['window'] ?? null) !== $window) $state = ['window' => $window, 'total' => 0, 'peers' => []];
        $peer = hash('sha256', telemetry_client_ip());
        $peerCount = (int)($state['peers'][$peer] ?? 0);
        if ($state['total'] >= telemetry_limit('PORTAL_TELEMETRY_REQUESTS_PER_MINUTE', 600, 10000) ||
            $peerCount >= telemetry_limit('PORTAL_TELEMETRY_PEER_REQUESTS_PER_MINUTE', 120, 10000) ||
            (!isset($state['peers'][$peer]) && count($state['peers']) >= 1024)) return false;
        $state['total']++;
        $state['peers'][$peer] = $peerCount + 1;
        rewind($handle); ftruncate($handle, 0);
        if (fwrite($handle, json_encode($state)) === false || !fflush($handle)) throw new RuntimeException('Quota update failed');
        return true;
    } finally { flock($handle, LOCK_UN); fclose($handle); }
}

function telemetry_health(?PDO $db): array {
    if (!$db) return ['state' => 'unavailable', 'lastReceivedAt' => null];
    $last = $db->query('SELECT MAX(ts) FROM (SELECT MAX(last_seen_at) ts FROM csp_violations UNION ALL SELECT MAX(last_seen_at) ts FROM client_errors)')->fetchColumn();
    $file = $db->query('PRAGMA database_list')->fetch(PDO::FETCH_ASSOC)['file'];
    $bytes = 0;
    foreach ([$file, $file . '-wal', $file . '-shm'] as $part) $bytes += is_file($part) ? filesize($part) : 0;
    $rows = (int)$db->query('SELECT (SELECT COUNT(*) FROM csp_violations) + (SELECT COUNT(*) FROM client_errors)')->fetchColumn();
    $limited = $bytes >= telemetry_limit('PORTAL_TELEMETRY_MAX_BYTES', 67108864, 1073741824) || $rows >= telemetry_limit('PORTAL_TELEMETRY_MAX_ROWS', 100000, 1000000);
    return ['state' => $limited ? 'capacity_limited' : ($last ? 'observed' : 'no_reports'), 'lastReceivedAt' => $last ?: null];
}

function telemetry_notify(PDO $db, array $alert): void {
    $url = portal_env('CSP_WEBHOOK_URL');
    if (!$url || !function_exists('curl_init')) return;
    $parts = parse_url($url);
    $allowed = ['https://hooks.slack.com', 'https://discord.com', 'https://discordapp.com'];
    foreach (explode(',', portal_env('PORTAL_TELEMETRY_WEBHOOK_ORIGINS') ?: '') as $entry) {
        $entry = strtolower(rtrim(trim($entry), '/'));
        if ($entry === '') continue;
        $configured = parse_url($entry);
        $host = is_array($configured) ? ($configured['host'] ?? '') : '';
        if (!$host || filter_var($host, FILTER_VALIDATE_IP) || !preg_match('/^[a-z0-9.-]+\.[a-z]{2,63}$/D', $host) ||
            preg_match('/(?:^|\.)(?:localhost|local|internal|test|invalid)$/D', $host) || $entry !== 'https://' . $host) return;
        $allowed[] = $entry;
    }
    if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment']) ||
        (isset($parts['port']) && $parts['port'] !== 443) || !in_array('https://' . strtolower($parts['host'] ?? ''), $allowed, true)) return;
    $key = (string)$alert['fingerprint'];
    $stmt = $db->prepare('SELECT last_notified_at FROM alert_notifications WHERE fingerprint = ?');
    $stmt->execute([$key]);
    if ((int)$stmt->fetchColumn() > time() - 3600) return;
    $handle = curl_init($url);
    curl_setopt_array($handle, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => json_encode(['text' => 'Telemetry alert: ' . ($alert['kind'] ?? 'csp') . '. Check the private dashboard.']),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'], CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT_MS => 1500, CURLOPT_FOLLOWLOCATION => false]);
    $result = curl_exec($handle);
    $status = curl_getinfo($handle, CURLINFO_HTTP_CODE);
    curl_close($handle);
    if ($result !== false && $status >= 200 && $status < 300) {
        $db->prepare('INSERT INTO alert_notifications(fingerprint,last_notified_at) VALUES (?,?) ON CONFLICT(fingerprint) DO UPDATE SET last_notified_at=excluded.last_notified_at')->execute([$key,time()]);
    }
}
