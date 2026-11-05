<?php
/**
 * dash Telemetry Collector (OpenLiteSpeed / PHP)
 * Endpoint routed from Cloudflare Tunnel: https://reports.takao.me/v1/{csp,error}
 *
 * Receives W3C CSP violation reports & client-side JS crashes,
 * filters browser extension noise, deduplicates into local SQLite (WAL),
 * executes automatic data retention GC (90 days), and dispatches critical alerts with cooldown.
 */

declare(strict_types=1);
require_once __DIR__ . '/telemetry.php';

// Backward compatibility helper functions for PHP < 8.0
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool {
        return $needle === '' || strpos($haystack, $needle) === 0;
    }
}
if (!function_exists('str_contains')) {
    function str_contains(string $haystack, string $needle): bool {
        return $needle === '' || strpos($haystack, $needle) !== false;
    }
}

// Disable caching and configure security headers
header('Cache-Control: no-store, private');
header('X-LiteSpeed-Cache-Control: no-cache');
header('X-Content-Type-Options: nosniff');

$isDebug = (isset($_GET['debug']) && $_GET['debug'] === '1');

// Handle CORS Preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    header('Access-Control-Max-Age: 86400');
    http_response_code(204);
    exit;
}

// Only POST is permitted
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST, OPTIONS');
    http_response_code(405);
    exit;
}

// Enforce max payload size (32 KiB)
$contentLength = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
if ($contentLength > 32768) {
    http_response_code(413);
    exit;
}

// Verify Content-Type
$contentType = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
$allowedTypes = ['application/csp-report', 'application/reports+json', 'application/json', 'text/plain', ''];
if (!in_array($contentType, $allowedTypes, true)) {
    http_response_code(415);
    exit;
}

// Read raw body with stream size guard
$rawBody = file_get_contents('php://input', false, null, 0, 32769);
if ($rawBody === false || strlen($rawBody) > 32768) {
    http_response_code(413);
    exit;
}

$input = json_decode($rawBody, true);
if (!is_array($input)) {
    http_response_code(400);
    exit;
}

// Check for client-side JavaScript error / crash
$isClientError = false;
$clientErrorItem = null;
if (isset($input['type']) && $input['type'] === 'client-error') {
    $isClientError = true;
    $clientErrorItem = $input;
} elseif (isset($input[0]) && is_array($input[0]) && ($input[0]['type'] ?? '') === 'client-error') {
    $isClientError = true;
    $clientErrorItem = $input[0];
}

// Extract CSP violation items
$items = [];
if (!$isClientError) {
    if (isset($input['csp-report']) && is_array($input['csp-report'])) {
        $items[] = $input['csp-report'];
    } elseif (isset($input[0]) && is_array($input[0])) {
        foreach ($input as $report) {
            if (is_array($report) && ($report['type'] ?? '') === 'csp-violation' && isset($report['body']) && is_array($report['body'])) {
                $items[] = $report['body'];
            }
        }
    }
}

if (!$isClientError && empty($items)) {
    http_response_code(204);
    exit;
}

// Reject malformed fields before PHP string casts can emit diagnostics.
foreach ($isClientError ? [$clientErrorItem] : $items as $item) {
    foreach (['message','source','filename','url','stack','documentURL','document-uri','blockedURL','blocked-uri','sourceFile','source-file','effectiveDirective','effective-directive','disposition'] as $field) {
        if (isset($item[$field]) && !is_string($item[$field])) { http_response_code(400); exit; }
    }
}

// Resolve private storage; never fall back to a document-root database.
try {
    $dataDir = telemetry_data_dir();
    if (count($items) > 20) { http_response_code(413); exit; }
    if (!telemetry_admit($dataDir)) { header('Retry-After: 60'); http_response_code(429); exit; }
    $bytes = 0;
    foreach (['telemetry.sqlite', 'telemetry.sqlite-wal', 'telemetry.sqlite-shm'] as $file) {
        $bytes += is_file($dataDir . '/' . $file) ? filesize($dataDir . '/' . $file) : 0;
    }
    if ($bytes >= telemetry_limit('PORTAL_TELEMETRY_MAX_BYTES', 67108864, 1073741824)) {
        header('Retry-After: 60'); http_response_code(503); exit;
    }
} catch (Throwable $e) { error_log('Telemetry storage or quota unavailable'); http_response_code(503); exit; }

// Verify SQLite PDO Extension
if (!extension_loaded('pdo_sqlite')) {
    error_log('dash collector: missing pdo_sqlite extension in PHP');
    http_response_code(500);
    exit;
}

// Verify Data Directory Write Permissions
if (!is_writable($dataDir)) {
    error_log('dash collector: data directory is not writable by web server user: ' . $dataDir);
    http_response_code(500);
    exit;
}

try {
    $dbPath = $dataDir . '/telemetry.sqlite';
    $pdo = telemetry_open($dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('PRAGMA journal_mode = WAL;');

    // Schema Initialization
    $pdo->exec('
        CREATE TABLE IF NOT EXISTS csp_violations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            screen TEXT NOT NULL,
            directive TEXT NOT NULL,
            blocked TEXT NOT NULL,
            disposition TEXT NOT NULL,
            raw_blocked_uri TEXT,
            count INTEGER DEFAULT 1,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            fingerprint TEXT UNIQUE,
            status TEXT DEFAULT "open"
        );
        CREATE INDEX IF NOT EXISTS idx_csp_service ON csp_violations(service);
        CREATE INDEX IF NOT EXISTS idx_csp_last_seen ON csp_violations(last_seen_at);
        CREATE INDEX IF NOT EXISTS idx_csp_status ON csp_violations(status);

        CREATE TABLE IF NOT EXISTS client_errors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            url TEXT NOT NULL,
            message TEXT NOT NULL,
            source TEXT NOT NULL,
            lineno INTEGER DEFAULT 0,
            colno INTEGER DEFAULT 0,
            stack TEXT,
            count INTEGER DEFAULT 1,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            fingerprint TEXT UNIQUE,
            status TEXT DEFAULT "open"
        );
        CREATE INDEX IF NOT EXISTS idx_client_err_service ON client_errors(service);
        CREATE INDEX IF NOT EXISTS idx_client_err_last_seen ON client_errors(last_seen_at);
        CREATE INDEX IF NOT EXISTS idx_client_err_status ON client_errors(status);

        CREATE TABLE IF NOT EXISTS alert_notifications (
            fingerprint TEXT PRIMARY KEY,
            last_notified_at INTEGER NOT NULL
        );
    ');

    // Auto-migration for existing databases: ensure status column exists
    $ensureStatusCol = function(PDO $db, string $table) {
        $cols = $db->query("PRAGMA table_info({$table})")->fetchAll(PDO::FETCH_ASSOC);
        $hasStatus = false;
        foreach ($cols as $col) {
            if ($col['name'] === 'status') { $hasStatus = true; break; }
        }
        if (!$hasStatus) {
            $db->exec("ALTER TABLE {$table} ADD COLUMN status TEXT DEFAULT 'open'");
        }
    };
    $ensureStatusCol($pdo, 'csp_violations');
    $ensureStatusCol($pdo, 'client_errors');

    // ====== Feature 1: Automatic Garbage Collection (90 days retention) ======
    // Deterministic hourly maintenance; no random retention lottery.
    if (time() - (int)@file_get_contents($dataDir . '/last-gc') >= 3600) {
        try {
            $cutoffIso = gmdate('Y-m-d\TH:i:s\Z', time() - (90 * 86400));
            $delCsp = $pdo->prepare('DELETE FROM csp_violations WHERE last_seen_at < :cutoff');
            $delCsp->execute([':cutoff' => $cutoffIso]);

            $delErr = $pdo->prepare('DELETE FROM client_errors WHERE last_seen_at < :cutoff');
            $delErr->execute([':cutoff' => $cutoffIso]);

            // Clean up alert cooldown records older than 7 days
            $sevenDaysAgo = time() - (7 * 86400);
            $pdo->prepare('DELETE FROM alert_notifications WHERE last_notified_at < :cutoff')
                ->execute([':cutoff' => $sevenDaysAgo]);

            $pdo->exec('PRAGMA optimize;');
            file_put_contents($dataDir . '/last-gc', (string)time(), LOCK_EX);
        } catch (\Throwable $gcError) {
            // Silently continue if GC fails
            error_log('dash collector GC notice: ' . $gcError->getMessage());
        }
    }

    $pdo->exec('BEGIN IMMEDIATE');
    $rowCount = (int)$pdo->query('SELECT (SELECT COUNT(*) FROM csp_violations) + (SELECT COUNT(*) FROM client_errors)')->fetchColumn();
    if ($rowCount >= telemetry_limit('PORTAL_TELEMETRY_MAX_ROWS', 100000, 1000000)) {
        header('Retry-After: 60'); http_response_code(503); exit;
    }

    $queryService = $_GET['service'] ?? null;
    $today = gmdate('Y-m-d');
    $now = gmdate('Y-m-d\TH:i:s\Z');

    // ====== Process Client-side JavaScript Error ======
    if ($isClientError && $clientErrorItem) {
        $rawMsg = trim((string)($clientErrorItem['message'] ?? 'Unknown Error'));
        $rawSource = (string)($clientErrorItem['source'] ?? $clientErrorItem['filename'] ?? '');
        $rawUrl = (string)($clientErrorItem['url'] ?? '');
        $lineno = (int)($clientErrorItem['lineno'] ?? 0);
        $colno = (int)($clientErrorItem['colno'] ?? 0);
        $stack = substr((string)($clientErrorItem['stack'] ?? ''), 0, 2000);

        // Ignore noise from browser extensions
        if (
            str_starts_with($rawSource, 'chrome-extension://') ||
            str_starts_with($rawSource, 'moz-extension://') ||
            str_starts_with($rawSource, 'safari-extension://')
        ) {
            http_response_code(204);
            exit;
        }

        // Identify Service
        $service = 'unknown';
        if ($queryService && is_string($queryService)) {
            $service = preg_replace('/[^a-zA-Z0-9_.-]/', '', substr($queryService, 0, 48));
        } elseif (!empty($rawUrl)) {
            $parsedUrl = parse_url($rawUrl);
            $host = $parsedUrl['host'] ?? '';
            if (str_contains($host, 'amga.jp')) {
                $service = 'houkago-link';
            } elseif (str_contains($host, 'takao.me')) {
                $service = 'manage-portal';
            } else {
                $service = preg_replace('/[^a-zA-Z0-9_.-]/', '', $host ?: 'unknown');
            }
        }

        $service = telemetry_service($service);
        $rawMsg = telemetry_message($rawMsg);
        $rawSource = telemetry_url($rawSource);
        $rawUrl = telemetry_url($rawUrl);
        $stack = '';
        $shortSource = $rawSource;
        $fingerprint = hash('sha256', "{$today}:{$service}:{$rawMsg}:{$shortSource}:{$lineno}");

        $stmt = $pdo->prepare('
            INSERT INTO client_errors (service, url, message, source, lineno, colno, stack, count, first_seen_at, last_seen_at, fingerprint, status)
            VALUES (:service, :url, :message, :source, :lineno, :colno, :stack, 1, :first_seen_at, :last_seen_at, :fingerprint, "open")
            ON CONFLICT(fingerprint) DO UPDATE SET
                count = client_errors.count + 1,
                last_seen_at = :last_seen_at
        ');

        $stmt->execute([
            ':service' => $service,
            ':url' => substr($rawUrl, 0, 512),
            ':message' => substr($rawMsg, 0, 512),
            ':source' => substr($rawSource, 0, 512),
            ':lineno' => $lineno,
            ':colno' => $colno,
            ':stack' => $stack,
            ':first_seen_at' => $now,
            ':last_seen_at' => $now,
            ':fingerprint' => $fingerprint
        ]);

        $pdo->exec('COMMIT');
        try { telemetry_notify($pdo, ['kind' => 'client_error', 'fingerprint' => $fingerprint]); }
        catch (Throwable $e) { error_log('Telemetry notification unavailable'); }
        http_response_code(204);
        exit;
    }

    $allowedDirectives = [
        'default-src', 'script-src', 'script-src-elem', 'script-src-attr',
        'style-src', 'style-src-elem', 'style-src-attr', 'connect-src',
        'img-src', 'font-src', 'frame-src', 'frame-ancestors', 'form-action',
        'base-uri', 'object-src', 'worker-src', 'manifest-src', 'media-src'
    ];

    $criticalAlerts = [];

    // ====== Process CSP Violations ======
    foreach ($items as $item) {
        $docUri = (string)($item['documentURL'] ?? $item['document-uri'] ?? '');
        $rawBlocked = (string)($item['blockedURL'] ?? $item['blocked-uri'] ?? '');
        $sourceFile = (string)($item['sourceFile'] ?? $item['source-file'] ?? '');

        // Noise Filtering: Ignore browser extension artifacts
        if (
            str_starts_with($rawBlocked, 'chrome-extension://') ||
            str_starts_with($rawBlocked, 'moz-extension://') ||
            str_starts_with($rawBlocked, 'safari-extension://') ||
            str_starts_with($sourceFile, 'chrome-extension://') ||
            str_starts_with($sourceFile, 'moz-extension://') ||
            str_starts_with($rawBlocked, 'about:blank')
        ) {
            continue;
        }

        // Identify Service Name
        $service = 'unknown';
        if ($queryService && is_string($queryService)) {
            $service = preg_replace('/[^a-zA-Z0-9_.-]/', '', substr($queryService, 0, 48));
        } elseif (!empty($docUri)) {
            $parsedDoc = parse_url($docUri);
            $host = $parsedDoc['host'] ?? '';
            if (str_contains($host, 'amga.jp')) {
                $service = 'houkago-link';
            } elseif (str_contains($host, 'takao.me')) {
                $service = 'manage-portal';
            } else {
                $service = preg_replace('/[^a-zA-Z0-9_.-]/', '', $host ?: 'unknown');
            }
        }

        $service = telemetry_service($service);

        // Extract Screen Identifier
        $screen = 'dashboard';
        if (!empty($docUri)) {
            $path = parse_url($docUri, PHP_URL_PATH) ?? '/';
            $parts = array_values(array_filter(explode('/', $path)));
            $screen = !empty($parts) ? end($parts) : 'root';
            $screen = preg_replace('/[^a-zA-Z0-9_-]/', '', substr($screen, 0, 32));
        }

        $screen = telemetry_screen($screen);

        // Normalize Directive
        $rawDirective = (string)($item['effectiveDirective'] ?? $item['effective-directive'] ?? '');
        $directive = in_array($rawDirective, $allowedDirectives, true) ? $rawDirective : 'other';

        // Categorize Blocked Source
        $blocked = 'other';
        if (in_array($rawBlocked, ['inline', 'eval', 'wasm-eval'], true)) {
            $blocked = $rawBlocked;
        } elseif (str_starts_with($rawBlocked, 'data:')) {
            $blocked = 'data';
        } elseif (str_starts_with($rawBlocked, 'blob:')) {
            $blocked = 'blob';
        } elseif (!empty($rawBlocked)) {
            $parsedBlocked = parse_url($rawBlocked);
            if (isset($parsedBlocked['host'])) {
                $blocked = 'external';
            }
        }

        $disposition = (($item['disposition'] ?? '') === 'report') ? 'report' : 'enforce';

        // Fingerprint Deduplication (Day-scoped)
        $fingerprint = hash('sha256', "{$today}:{$service}:{$screen}:{$directive}:{$blocked}:{$disposition}");

        $stmt = $pdo->prepare('
            INSERT INTO csp_violations (service, screen, directive, blocked, disposition, raw_blocked_uri, count, first_seen_at, last_seen_at, fingerprint, status)
            VALUES (:service, :screen, :directive, :blocked, :disposition, :raw_blocked_uri, 1, :first_seen_at, :last_seen_at, :fingerprint, "open")
            ON CONFLICT(fingerprint) DO UPDATE SET
                count = csp_violations.count + 1,
                last_seen_at = :last_seen_at
        ');

        $stmt->execute([
            ':service' => $service,
            ':screen' => $screen,
            ':directive' => $directive,
            ':blocked' => $blocked,
            ':disposition' => $disposition,
            ':raw_blocked_uri' => telemetry_url($rawBlocked),
            ':first_seen_at' => $now,
            ':last_seen_at' => $now,
            ':fingerprint' => $fingerprint
        ]);

        // Check for Critical Injections (eval or unexpected script-src)
        if ($directive === 'script-src' || $blocked === 'eval') {
            $criticalAlerts[] = [
                'service' => $service,
                'screen' => $screen,
                'directive' => $directive,
                'blocked' => $blocked,
                'raw_uri' => telemetry_url($rawBlocked),
                'fingerprint' => $fingerprint,
                'time' => $now
            ];
        }
    }

    $pdo->exec('COMMIT');
    if (!empty($criticalAlerts)) {
        try { telemetry_notify($pdo, $criticalAlerts[0]); }
        catch (Throwable $e) { error_log('Telemetry notification unavailable'); }
    }

    http_response_code(204);

} catch (\Throwable $e) {
    error_log('dash collector runtime error');
    http_response_code(500);
    exit;
}
