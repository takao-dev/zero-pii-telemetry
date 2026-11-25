<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') exit(77);
$calls = 0; $status = 500; $options = [];
$transport = static function(string $url, array $request) use (&$calls, &$status, &$options): array {
    $calls++;
    $options = ['url' => $url] + $request;
    return ['body' => 'synthetic', 'status' => $status];
};
require_once dirname(__DIR__) . '/telemetry.php';
function check(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
$db = new PDO('sqlite::memory:');
$db->exec('CREATE TABLE alert_notifications(fingerprint TEXT PRIMARY KEY,last_notified_at INTEGER NOT NULL)');
$db->exec('CREATE TABLE alert_notification_quota(window_start INTEGER PRIMARY KEY,attempt_count INTEGER NOT NULL DEFAULT 0)');
putenv('PORTAL_TELEMETRY_WEBHOOKS_PER_HOUR=3');
putenv('CSP_WEBHOOK_URL=https://hooks.slack.com/services/synthetic');
$alert = ['fingerprint' => 'synthetic', 'kind' => 'client_error'];
telemetry_notify($db, $alert, $transport);
check((int)$db->query('SELECT COUNT(*) FROM alert_notifications')->fetchColumn() === 0, 'Failed delivery consumed cooldown');
check($options['followRedirects'] === false, 'Redirects enabled');
check(strpos($options['body'], 'client_error') !== false, 'Client error notification missing');
$status = 204;
telemetry_notify($db, $alert, $transport);
check((int)$db->query('SELECT COUNT(*) FROM alert_notifications')->fetchColumn() === 1, 'Success not recorded');
$before = $calls;
telemetry_notify($db, $alert, $transport);
check($calls === $before, 'Cooldown ignored');
putenv('CSP_WEBHOOK_URL=http://127.0.0.1/internal');
telemetry_notify($db, ['fingerprint' => 'unsafe'], $transport);
check($calls === $before, 'Unsafe destination reached transport');
putenv('CSP_WEBHOOK_URL=https://monitor.example.com/hook');
putenv('PORTAL_TELEMETRY_WEBHOOK_ORIGINS=https://monitor.example.com');
telemetry_notify($db, ['fingerprint' => 'custom'], $transport);
check($calls === $before + 1, 'Approved custom destination rejected');
telemetry_notify($db, ['fingerprint' => 'hourly-limit'], $transport);
check($calls === $before + 1, 'Global hourly notification cap ignored');
check((int)$db->query('SELECT SUM(attempt_count) FROM alert_notification_quota')->fetchColumn() === 3, 'Hourly attempts not capped');
echo "Notification regression: delivery, cooldown, destination validation, and global hourly cap passed\n";
