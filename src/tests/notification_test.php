<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli' || extension_loaded('curl')) exit(77);
foreach (['CURLOPT_POST','CURLOPT_POSTFIELDS','CURLOPT_HTTPHEADER','CURLOPT_RETURNTRANSFER','CURLOPT_TIMEOUT_MS','CURLOPT_FOLLOWLOCATION','CURLINFO_HTTP_CODE'] as $i => $name) define($name, $i + 1);
$calls = 0; $status = 500; $options = [];
function curl_init(string $url) { $GLOBALS['calls']++; return $url; }
function curl_setopt_array($handle, array $options): bool { $GLOBALS['options'] = $options; return true; }
function curl_exec($handle) { return 'synthetic'; }
function curl_getinfo($handle, $key) { return $GLOBALS['status']; }
function curl_close($handle): void {}
require_once dirname(__DIR__) . '/telemetry.php';
function check(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
$db = new PDO('sqlite::memory:');
$db->exec('CREATE TABLE alert_notifications(fingerprint TEXT PRIMARY KEY,last_notified_at INTEGER NOT NULL)');
putenv('CSP_WEBHOOK_URL=https://hooks.slack.com/services/synthetic');
$alert = ['fingerprint' => 'synthetic', 'kind' => 'client_error'];
telemetry_notify($db, $alert);
check((int)$db->query('SELECT COUNT(*) FROM alert_notifications')->fetchColumn() === 0, 'Failed delivery consumed cooldown');
check($options[CURLOPT_FOLLOWLOCATION] === false, 'Redirects enabled');
check(strpos($options[CURLOPT_POSTFIELDS], 'client_error') !== false, 'Client error notification missing');
$status = 204;
telemetry_notify($db, $alert);
check((int)$db->query('SELECT COUNT(*) FROM alert_notifications')->fetchColumn() === 1, 'Success not recorded');
$before = $calls;
telemetry_notify($db, $alert);
check($calls === $before, 'Cooldown ignored');
putenv('CSP_WEBHOOK_URL=http://127.0.0.1/internal');
telemetry_notify($db, ['fingerprint' => 'unsafe']);
check($calls === $before, 'Unsafe destination reached transport');
putenv('CSP_WEBHOOK_URL=https://monitor.example.com/hook');
putenv('PORTAL_TELEMETRY_WEBHOOK_ORIGINS=https://monitor.example.com');
telemetry_notify($db, ['fingerprint' => 'custom']);
check($calls === $before + 1, 'Approved custom destination rejected');
echo "Notification regression: success, failure, cooldown, redirect refusal, client errors, approved custom destination passed\n";
