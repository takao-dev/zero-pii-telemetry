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
    foreach ($db->query('SELECT id,service,url,message,source FROM client_errors')->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $db->prepare('UPDATE client_errors SET service=?,url=?,message=?,source=?,stack=? WHERE id=?')->execute([
            telemetry_service($row['service']), telemetry_url($row['url']), telemetry_message($row['message']), telemetry_url($row['source']), '', $row['id']
        ]);
    }
    foreach ($db->query('SELECT id,service,screen,raw_blocked_uri FROM csp_violations')->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $db->prepare('UPDATE csp_violations SET service=?,screen=?,raw_blocked_uri=? WHERE id=?')->execute([
            telemetry_service($row['service']), telemetry_screen($row['screen']), telemetry_url($row['raw_blocked_uri'] ?? ''), $row['id']
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
