<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/telemetry.php';
// Run offline with collectors stopped. This remains available when ingest is capped.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
try {
    $dir = telemetry_data_dir();
    $path = $dir . '/telemetry.sqlite';
    if (!is_file($path)) throw new RuntimeException('Missing database');
    $db = telemetry_open($path);
    $cutoff = gmdate('Y-m-d\TH:i:s\Z', time() - 90 * 86400);
    $db->beginTransaction();
    foreach (['csp_violations', 'client_errors'] as $table) {
        $db->prepare('DELETE FROM ' . $table . ' WHERE last_seen_at < ?')->execute([$cutoff]);
    }
    $db->prepare('DELETE FROM alert_notifications WHERE last_notified_at < ?')->execute([time() - 7 * 86400]);
    $db->commit();
    $db->exec('PRAGMA wal_checkpoint(TRUNCATE)');
    $db->exec('VACUUM');
    $db->exec('PRAGMA wal_checkpoint(TRUNCATE)');
    file_put_contents($dir . '/last-gc', (string)time(), LOCK_EX);
    echo "Retention maintenance complete. Check capacity before restarting collectors.\n";
} catch (Throwable $e) { fwrite(STDERR, "Maintenance failed; keep collection stopped and inspect locally.\n"); exit(1); }
