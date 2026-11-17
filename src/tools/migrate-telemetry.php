<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/telemetry.php';

// Explicit offline operation. Never moves or deletes the original database.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
if (count($argv) !== 2) { fwrite(STDERR, "Usage: php tools/migrate-telemetry.php OLD_DATABASE\n"); exit(1); }
$source = realpath($argv[1]);
if (!$source || !is_file($source)) { fwrite(STDERR, "Source database not found\n"); exit(1); }
$dir = telemetry_data_dir();
$target = $dir . '/telemetry.sqlite';
$pending = $dir . '/telemetry.migrating';
if (file_exists($target) || file_exists($pending)) { fwrite(STDERR, "Destination already exists; refusing overwrite\n"); exit(1); }
try {
    $old = telemetry_open($source);
    $old->exec('VACUUM INTO ' . $old->quote($pending));
    $db = telemetry_open($pending);
    $db->exec('PRAGMA secure_delete = ON');
    $db->beginTransaction();
    foreach ($db->query('SELECT id,service,url,message,source,lineno,colno,count,first_seen_at,last_seen_at FROM client_errors')->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $db->prepare('UPDATE client_errors SET service=?,url=?,message=?,source=?,lineno=?,colno=?,stack=?,count=?,first_seen_at=?,last_seen_at=? WHERE id=?')->execute([
            telemetry_service((string)$row['service']), telemetry_url(substr((string)$row['url'], 0, 2048)),
            telemetry_message(substr((string)$row['message'], 0, 2048)), telemetry_url(substr((string)$row['source'], 0, 2048)),
            max(0, (int)$row['lineno']), max(0, (int)$row['colno']), '', max(0, (int)$row['count']),
            telemetry_iso_timestamp($row['first_seen_at']) ?? gmdate('Y-m-d\\TH:i:s\\Z'),
            telemetry_iso_timestamp($row['last_seen_at']) ?? gmdate('Y-m-d\\TH:i:s\\Z'), $row['id']
        ]);
    }
    foreach ($db->query('SELECT id,service,screen,directive,blocked,disposition,raw_blocked_uri,count,first_seen_at,last_seen_at FROM csp_violations')->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $db->prepare('UPDATE csp_violations SET service=?,screen=?,directive=?,blocked=?,disposition=?,raw_blocked_uri=?,count=?,first_seen_at=?,last_seen_at=? WHERE id=?')->execute([
            telemetry_service((string)$row['service']), telemetry_screen((string)$row['screen']),
            telemetry_csp_directive((string)$row['directive']), telemetry_blocked_class((string)$row['blocked']),
            ($row['disposition'] ?? '') === 'report' ? 'report' : 'enforce',
            telemetry_url(substr((string)($row['raw_blocked_uri'] ?? ''), 0, 2048)), max(0, (int)$row['count']),
            telemetry_iso_timestamp($row['first_seen_at']) ?? gmdate('Y-m-d\\TH:i:s\\Z'),
            telemetry_iso_timestamp($row['last_seen_at']) ?? gmdate('Y-m-d\\TH:i:s\\Z'), $row['id']
        ]);
    }
    $db->commit();
    $db->exec('VACUUM');
    $db = null; $old = null;
    chmod($pending, 0600);
    if (!rename($pending, $target)) throw new RuntimeException('Migration publish failed');
    fwrite(STDOUT, "Private sanitized database prepared. Original database retained; review before restarting collectors.\n");
} catch (Throwable $e) {
    fwrite(STDERR, "Migration failed. Do not enable collection; inspect private staging files locally.\n");
    exit(1);
}
