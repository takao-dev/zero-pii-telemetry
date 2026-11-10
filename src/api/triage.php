<?php
/**
 * dash Telemetry Triage API
 * Updates resolution status of CSP incidents or Client errors.
 * Supported status values: "open", "resolved", "ignored"
 */

declare(strict_types=1);
require_once dirname(__DIR__) . '/telemetry.php';
telemetry_require_admin();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-cache, no-store, private');
header('X-LiteSpeed-Cache-Control: no-cache');
header('X-Content-Type-Options: nosniff');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method not allowed. Use POST.']);
    exit;
}

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$expectedOrigin = rtrim(portal_env('PORTAL_MANAGEMENT_ORIGIN') ?: '', '/');
if (!hash_equals($expectedOrigin, $origin) ||
    ($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '') === 'cross-site' ||
    strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0])) !== 'application/json') {
    http_response_code(403); echo json_encode(['status' => 'error', 'message' => 'Untrusted management request']); exit;
}
$rawInput = file_get_contents('php://input', false, null, 0, 8193);
if ($rawInput === false || strlen($rawInput) > 8192) { http_response_code(413); exit; }
$data = json_decode($rawInput, true);

if (!is_array($data)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid JSON payload.']);
    exit;
}

$type = (string)($data['type'] ?? '');
$id = (int)($data['id'] ?? 0);
$newStatus = (string)($data['status'] ?? '');

$allowedStatuses = ['open', 'resolved', 'ignored'];
if (!in_array($newStatus, $allowedStatuses, true)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid status. Must be one of: open, resolved, ignored.']);
    exit;
}

if ($id <= 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid record ID.']);
    exit;
}

$table = '';
if ($type === 'csp') {
    $table = 'csp_violations';
} elseif ($type === 'client_error') {
    $table = 'client_errors';
} else {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid type. Must be "csp" or "client_error".']);
    exit;
}

try { $dbPath = telemetry_data_dir() . '/telemetry.sqlite'; }
catch (Throwable $e) { http_response_code(503); echo json_encode(['status' => 'error', 'message' => 'Telemetry storage unavailable']); exit; }
if (!file_exists($dbPath)) {
    http_response_code(404);
    echo json_encode(['status' => 'error', 'message' => 'Telemetry database not found.']);
    exit;
}

try {
    $pdo = telemetry_open($dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Verify table has status column
    $cols = $pdo->query("PRAGMA table_info({$table})")->fetchAll(PDO::FETCH_ASSOC);
    $hasStatus = false;
    foreach ($cols as $col) {
        if ($col['name'] === 'status') { $hasStatus = true; break; }
    }
    if (!$hasStatus) {
        $pdo->exec("ALTER TABLE {$table} ADD COLUMN status TEXT DEFAULT 'open'");
    }

    $stmt = $pdo->prepare("UPDATE {$table} SET status = :status WHERE id = :id");
    $stmt->execute([':status' => $newStatus, ':id' => $id]);

    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode(['status' => 'error', 'message' => 'Record not found.']);
        exit;
    }

    echo json_encode([
        'status' => 'ok',
        'type' => $type,
        'id' => $id,
        'newStatus' => $newStatus,
        'updatedAt' => gmdate('Y-m-d\TH:i:s\Z')
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

} catch (\Throwable $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Database operation failed']);
}
