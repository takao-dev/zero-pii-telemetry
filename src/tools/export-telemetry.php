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

$daysText = (string)($options['days'] ?? '30');
if (!ctype_digit($daysText) || (int)$daysText < 1 || (int)$daysText > 3650) {
    fwrite(STDERR, "Error: --days must be between 1 and 3650\n");
    exit(1);
}
$days = (int)$daysText;
$type = strtolower((string)($options['type'] ?? 'all'));
$serviceFilter = isset($options['service']) ? trim((string)$options['service']) : null;
if (!in_array($type, ['all', 'csp', 'error'], true)) {
    fwrite(STDERR, "Error: --type must be all, csp, or error\n");
    exit(1);
}
if ($serviceFilter !== null && !preg_match('/^[a-zA-Z0-9_.-]{1,48}$/D', $serviceFilter)) {
    fwrite(STDERR, "Error: --service must contain 1-48 letters, numbers, dots, underscores, or hyphens\n");
    exit(1);
}
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

$since = gmdate('Y-m-d\\TH:i:s\\Z', time() - ($days * 86400));
$results = [];

// Export CSP violations
if ($type === 'all' || $type === 'csp') {
    $sql = "SELECT 'csp' AS record_type, service, directive, raw_blocked_uri AS uri_or_source, count, first_seen_at, last_seen_at FROM csp_violations WHERE last_seen_at >= :since";
    $params = [':since' => $since];
    if ($serviceFilter !== null) {
        $sql .= " AND service = :service";
        $params[':service'] = $serviceFilter;
    }
    $sql .= " ORDER BY last_seen_at DESC";
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $results[] = [
            'record_type' => 'csp',
            'service' => telemetry_service((string)$row['service']),
            'directive' => telemetry_csp_directive((string)$row['directive']),
            'uri_or_source' => telemetry_url(substr((string)$row['uri_or_source'], 0, 2048)),
            'count' => max(0, (int)$row['count']),
            'first_seen_at' => telemetry_iso_timestamp($row['first_seen_at']),
            'last_seen_at' => telemetry_iso_timestamp($row['last_seen_at']),
        ];
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
        $results[] = [
            'record_type' => 'error',
            'service' => telemetry_service((string)$row['service']),
            'directive' => telemetry_message(substr((string)$row['directive'], 0, 2048)),
            'uri_or_source' => telemetry_url(substr((string)$row['uri_or_source'], 0, 2048)),
            'count' => max(0, (int)$row['count']),
            'first_seen_at' => telemetry_iso_timestamp($row['first_seen_at']),
            'last_seen_at' => telemetry_iso_timestamp($row['last_seen_at']),
        ];
    }
}

$output = '';
if ($format === 'json') {
    $output = json_encode([
        'exported_at' => date('c'),
        'period_days' => $days,
        'record_count' => count($results),
        'records' => $results,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR) . "\n";
} else {
    $sanitizeCsv = static function(mixed $val): string {
        $str = (string)$val;
        if ($str !== '' && preg_match('/^[\x00-\x20]*[=+\-@]/', $str)) {
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
            $r['first_seen_at'] ?? '',
            $r['last_seen_at'] ?? '',
        ]);
    }
    rewind($fp);
    $output = stream_get_contents($fp);
    fclose($fp);
}

if ($outputPath !== null) {
    $previousMask = umask(0077);
    $fp = @fopen($outputPath, 'xb');
    umask($previousMask);
    if (!$fp) {
        fwrite(STDERR, "Failed to create export file (existing files are never overwritten)\n");
        exit(1);
    }
    $created = true;
    try {
        if (DIRECTORY_SEPARATOR !== '\\' && !@chmod($outputPath, 0600)) throw new RuntimeException('Export permissions unavailable');
        $offset = 0;
        while ($offset < strlen($output)) {
            $written = fwrite($fp, substr($output, $offset));
            if ($written === false || $written === 0) throw new RuntimeException('Export write failed');
            $offset += $written;
        }
        if (!fflush($fp)) throw new RuntimeException('Export flush failed');
        fclose($fp);
        $fp = null;
    } catch (Throwable $e) {
        if (is_resource($fp)) fclose($fp);
        if ($created) @unlink($outputPath);
        fwrite(STDERR, "Failed to write the export file\n");
        exit(1);
    }
    fwrite(STDERR, "Exported " . count($results) . " records to {$outputPath}\n");
} else {
    echo $output;
}
