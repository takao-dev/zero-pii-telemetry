<?php
declare(strict_types=1);

/**
 * Zero-PII Telemetry Export Tool
 * Exports aggregated CSP violations and client JS exceptions in CSV or JSON format.
 *
 * Usage:
 *   php src/tools/export-telemetry.php [--format=csv|json] [--days=30] [--type=all|csp|error] [--service=name] [--output=path]
 */

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This tool must be run from the command line.\n");
    exit(1);
}

require_once dirname(__DIR__) . '/telemetry.php';

$options = getopt('', ['format::', 'days::', 'type::', 'service::', 'output::', 'help']);

if (isset($options['help'])) {
    echo <<<HELP
Zero-PII Telemetry Export Tool

Usage:
  php export-telemetry.php [options]

Options:
  --format=csv|json    Output format (default: json)
  --days=N             Export records from the past N days (default: 30)
  --type=all|csp|error Report type to export (default: all)
  --service=NAME       Filter by specific service name
  --output=PATH        Write output directly to file instead of stdout
  --help               Display this help message

HELP;
    exit(0);
}

$format = strtolower((string)($options['format'] ?? 'json'));
if (!in_array($format, ['csv', 'json'], true)) {
    fwrite(STDERR, "Error: --format must be either 'csv' or 'json'\n");
    exit(1);
}

$days = max(1, (int)($options['days'] ?? 30));
$type = strtolower((string)($options['type'] ?? 'all'));
$serviceFilter = isset($options['service']) ? trim((string)$options['service']) : null;
$outputPath = isset($options['output']) ? (string)$options['output'] : null;

try {
    $dir = telemetry_data_dir();
    $dbPath = $dir . '/telemetry.sqlite';
    if (!is_file($dbPath)) {
        fwrite(STDERR, "No telemetry database found at: {$dbPath}\n");
        exit(0);
    }
    $db = telemetry_open($dbPath);
} catch (Throwable $e) {
    fwrite(STDERR, "Database connection error: " . $e->getMessage() . "\n");
    exit(1);
}

$since = time() - ($days * 86400);
$results = [];

// Export CSP violations
if ($type === 'all' || $type === 'csp') {
    $sql = "SELECT 'csp' AS record_type, service, directive, blocked_uri AS uri_or_source, count, first_seen_at, last_seen_at FROM csp_violations WHERE last_seen_at >= :since";
    $params = [':since' => $since];
    if ($serviceFilter !== null) {
        $sql .= " AND service = :service";
        $params[':service'] = $serviceFilter;
    }
    $sql .= " ORDER BY last_seen_at DESC";
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $results[] = $row;
    }
}

// Export Client JS errors
if ($type === 'all' || $type === 'error') {
    $sql = "SELECT 'error' AS record_type, service, message AS directive, source AS uri_or_source, count, first_seen_at, last_seen_at FROM client_errors WHERE last_seen_at >= :since";
    $params = [':since' => $since];
    if ($serviceFilter !== null) {
        $sql .= " AND service = :service";
        $params[':service'] = $serviceFilter;
    }
    $sql .= " ORDER BY last_seen_at DESC";
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $results[] = $row;
    }
}

$output = '';
if ($format === 'json') {
    $output = json_encode([
        'exported_at' => date('c'),
        'period_days' => $days,
        'record_count' => count($results),
        'records' => $results,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
} else {
    $sanitizeCsv = static function(mixed $val): string {
        $str = (string)$val;
        if ($str !== '' && in_array($str[0], ['=', '+', '-', '@', "\t", "\r"], true)) {
            return "'" . $str;
        }
        return $str;
    };
    $fp = fopen('php://temp', 'r+');
    fputcsv($fp, ['record_type', 'service', 'directive_or_message', 'uri_or_source', 'occurrences', 'first_seen_iso', 'last_seen_iso']);
    foreach ($results as $r) {
        fputcsv($fp, [
            $sanitizeCsv($r['record_type']),
            $sanitizeCsv($r['service']),
            $sanitizeCsv($r['directive']),
            $sanitizeCsv($r['uri_or_source']),
            $r['count'],
            date('c', (int)$r['first_seen_at']),
            date('c', (int)$r['last_seen_at']),
        ]);
    }
    rewind($fp);
    $output = stream_get_contents($fp);
    fclose($fp);
}

if ($outputPath !== null) {
    if (file_put_contents($outputPath, $output) === false) {
        fwrite(STDERR, "Failed to write export to {$outputPath}\n");
        exit(1);
    }
    fwrite(STDERR, "Exported " . count($results) . " records to {$outputPath}\n");
} else {
    echo $output;
}
