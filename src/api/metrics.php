<?php
/**
 * dash Telemetry & Traffic Metrics API
 * Returns aggregated statistics, cross-site traffic (PV/Visits from Operations),
 * and incident records (CSP & Client JS Errors) with triage status for the dashboard UI.
 */

declare(strict_types=1);
require_once dirname(__DIR__) . '/telemetry.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-cache, no-store, private');
header('X-LiteSpeed-Cache-Control: no-cache');
header('X-Content-Type-Options: nosniff');

$dbPath = null;
try { $dbPath = telemetry_data_dir() . '/telemetry.sqlite'; } catch (Throwable $e) { /* explicit unavailable below */ }

// ====== 1. Load Traffic Data from Operations ======
$operationsDataDir = portal_env('OPERATIONS_DATA_DIR') ?: null;
if (!$operationsDataDir) {
    $candidateDirs = [
        'C:/dev/website/hugo/Operations/data',
        dirname(__DIR__, 4) . '/website/hugo/Operations/data',
        '/var/www/Operations/data',
        '/var/www/website/hugo/Operations/data',
        '/var/www/operations/data',
        $dataDir . '/operations',
    ];
    foreach ($candidateDirs as $dir) {
        if (is_dir($dir)) {
            $operationsDataDir = $dir;
            break;
        }
    }
}

function parsePopularJson(string $filePath): array {
    if (!file_exists($filePath)) {
        return ['views' => 0, 'visits' => 0, 'topPages' => []];
    }
    $raw = @file_get_contents($filePath);
    if ($raw === false) {
        return ['views' => 0, 'visits' => 0, 'topPages' => []];
    }
    $json = json_decode($raw, true);
    if (!is_array($json)) {
        return ['views' => 0, 'visits' => 0, 'topPages' => []];
    }
    $views = 0;
    $visits = 0;
    foreach ($json as $item) {
        $views += (int)($item['pageViews'] ?? 0);
        $visits += (int)($item['visits'] ?? 0);
    }
    $topPages = array_slice($json, 0, 5);
    return [
        'views' => $views,
        'visits' => $visits,
        'topPages' => array_map(function($p) {
            return [
                'path' => $p['path'] ?? '',
                'pageViews' => (int)($p['pageViews'] ?? 0),
                'visits' => (int)($p['visits'] ?? 0),
            ];
        }, $topPages)
    ];
}

$trafficSites = [];
$totalTodayViews = 0;
$totalWeekViews = 0;
$totalMonthViews = 0;

if ($operationsDataDir && is_dir($operationsDataDir)) {
    $entries = scandir($operationsDataDir);
    if ($entries !== false) {
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..' || !is_dir($operationsDataDir . '/' . $entry)) {
                continue;
            }
            $domain = $entry;
            $popularDir = $operationsDataDir . '/' . $domain . '/popular';
            if (!is_dir($popularDir)) {
                continue;
            }

            $dayData = parsePopularJson($popularDir . '/day.json');
            $weekData = parsePopularJson($popularDir . '/week.json');
            $monthData = parsePopularJson($popularDir . '/month.json');

            $totalTodayViews += $dayData['views'];
            $totalWeekViews += $weekData['views'];
            $totalMonthViews += $monthData['views'];

            $trafficSites[$domain] = [
                'domain' => $domain,
                'todayViews' => $dayData['views'],
                'todayVisits' => $dayData['visits'],
                'weekViews' => $weekData['views'],
                'weekVisits' => $weekData['visits'],
                'monthViews' => $monthData['views'],
                'monthVisits' => $monthData['visits'],
                'topPages' => $dayData['topPages'],
                'cacheStatus' => '7d_edge_ttl', // Optimized Cloudflare Edge TTL
            ];
        }
    }
    ksort($trafficSites);
}

// ====== 2. Query SQLite Telemetry Database ======
$pdo = null;
if ($dbPath && file_exists($dbPath)) {
    try {
        $pdo = telemetry_open($dbPath);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Ensure status columns exist
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
    } catch (Throwable $e) {
        $pdo = null;
    }
}

$serviceFilter = $_GET['service'] ?? null;
$statusFilter = $_GET['status'] ?? 'open'; // 'open', 'all', 'resolved', 'ignored'

$whereClauses = [];
$params = [];

if (!empty($serviceFilter) && is_string($serviceFilter) && $serviceFilter !== 'all') {
    $whereClauses[] = 'service = :service';
    $params[':service'] = $serviceFilter;
}

if (!empty($statusFilter) && $statusFilter !== 'all') {
    $whereClauses[] = 'COALESCE(status, "open") = :status';
    $params[':status'] = $statusFilter;
}

$whereSql = !empty($whereClauses) ? ' WHERE ' . implode(' AND ', $whereClauses) : '';

$summaryRow = ['total_reports' => 0, 'unique_signatures' => 0, 'critical_count' => 0];
$clientErrSummaryRow = ['total_client_errors' => 0, 'unique_client_errors' => 0];
$services = [];
$directives = [];
$dailyTrend = [];
$incidents = [];
$clientErrors = [];

// Aggregate error counts per site (open/unresolved only for health metrics)
$cspCountsBySite = [];
$criticalCspBySite = [];
$clientErrorsBySite = [];

if ($pdo) {
    try {
        // 1. Summary Aggregates (CSP - all statuses for totals)
        $summaryStmt = $pdo->prepare("
            SELECT 
                COALESCE(SUM(count), 0) as total_reports,
                COUNT(*) as unique_signatures,
                COALESCE(SUM(CASE WHEN directive = 'script-src' OR blocked = 'eval' THEN count ELSE 0 END), 0) as critical_count
            FROM csp_violations
            " . (!empty($serviceFilter) && $serviceFilter !== 'all' ? 'WHERE service = :s' : '') . "
        ");
        if (!empty($serviceFilter) && $serviceFilter !== 'all') {
            $summaryStmt->execute([':s' => $serviceFilter]);
        } else {
            $summaryStmt->execute();
        }
        $summaryRow = $summaryStmt->fetch(PDO::FETCH_ASSOC) ?: $summaryRow;

        // 1.b Summary Aggregates (Client Errors)
        $clientErrSummaryStmt = $pdo->prepare("
            SELECT 
                COALESCE(SUM(count), 0) as total_client_errors,
                COUNT(*) as unique_client_errors
            FROM client_errors
            " . (!empty($serviceFilter) && $serviceFilter !== 'all' ? 'WHERE service = :s' : '') . "
        ");
        if (!empty($serviceFilter) && $serviceFilter !== 'all') {
            $clientErrSummaryStmt->execute([':s' => $serviceFilter]);
        } else {
            $clientErrSummaryStmt->execute();
        }
        $clientErrSummaryRow = $clientErrSummaryStmt->fetch(PDO::FETCH_ASSOC) ?: $clientErrSummaryRow;

        // 2. Active Services List
        $servicesStmt = $pdo->query("
            SELECT DISTINCT service FROM (
                SELECT service FROM csp_violations
                UNION
                SELECT service FROM client_errors
            ) WHERE service IS NOT NULL AND service != ''
            ORDER BY service ASC
        ");
        $services = $servicesStmt->fetchAll(PDO::FETCH_COLUMN);

        // 3. Directive Breakdown
        $dirStmt = $pdo->prepare("
            SELECT directive, SUM(count) as count
            FROM csp_violations
            {$whereSql}
            GROUP BY directive
            ORDER BY count DESC
            LIMIT 10
        ");
        $dirStmt->execute($params);
        $directives = $dirStmt->fetchAll(PDO::FETCH_ASSOC);

        // 4. Daily Trend
        $trendStmt = $pdo->prepare("
            SELECT substr(last_seen_at, 1, 10) as day, SUM(count) as count
            FROM csp_violations
            {$whereSql}
            GROUP BY day
            ORDER BY day DESC
            LIMIT 7
        ");
        $trendStmt->execute($params);
        $dailyTrend = array_reverse($trendStmt->fetchAll(PDO::FETCH_ASSOC));

        // 5. Recent Incidents (with status)
        $incidentsStmt = $pdo->prepare("
            SELECT id, service, screen, directive, blocked, disposition, raw_blocked_uri, count, first_seen_at, last_seen_at, COALESCE(status, 'open') as status
            FROM csp_violations
            {$whereSql}
            ORDER BY last_seen_at DESC
            LIMIT 100
        ");
        $incidentsStmt->execute($params);
        $incidents = $incidentsStmt->fetchAll(PDO::FETCH_ASSOC);

        // 6. Recent Client Errors (with status)
        $clientErrorsStmt = $pdo->prepare("
            SELECT id, service, url, message, source, lineno, colno, stack, count, first_seen_at, last_seen_at, COALESCE(status, 'open') as status
            FROM client_errors
            {$whereSql}
            ORDER BY last_seen_at DESC
            LIMIT 100
        ");
        $clientErrorsStmt->execute($params);
        $clientErrors = $clientErrorsStmt->fetchAll(PDO::FETCH_ASSOC);

        // Group active (open) error counts per site for cross-site health matrix
        $cspSiteStmt = $pdo->query("
            SELECT service, 
                   SUM(count) as total_count,
                   SUM(CASE WHEN directive = 'script-src' OR blocked = 'eval' THEN count ELSE 0 END) as critical_count
            FROM csp_violations
            WHERE COALESCE(status, 'open') = 'open'
            GROUP BY service
        ");
        while ($row = $cspSiteStmt->fetch(PDO::FETCH_ASSOC)) {
            $s = telemetry_service((string)$row['service']);
            $cspCountsBySite[$s] = ($cspCountsBySite[$s] ?? 0) + (int)$row['total_count'];
            $criticalCspBySite[$s] = (int)$row['critical_count'];
        }

        $errSiteStmt = $pdo->query("
            SELECT service, SUM(count) as total_count
            FROM client_errors
            WHERE COALESCE(status, 'open') = 'open'
            GROUP BY service
        ");
        while ($row = $errSiteStmt->fetch(PDO::FETCH_ASSOC)) {
            $s = telemetry_service((string)$row['service']);
            $clientErrorsBySite[$s] = ($clientErrorsBySite[$s] ?? 0) + (int)$row['total_count'];
        }

    } catch (Throwable $e) {
        $pdo = null; // Failed queries cannot become a healthy zero.
    }
}

// ====== 3. Merge Sites Overview Matrix ======
$sitesOverview = [];

$extractErrorCounts = function(string $domain) use (&$cspCountsBySite, &$criticalCspBySite, &$clientErrorsBySite): array {
    $hyphen = str_replace('.', '-', $domain);
    $short = explode('.', $domain)[0];

    $csp = 0;
    $crit = 0;
    $err = 0;

    foreach ([$domain, $hyphen, $short] as $key) {
        if (isset($cspCountsBySite[$key])) {
            $csp += $cspCountsBySite[$key];
            unset($cspCountsBySite[$key]);
        }
        if (isset($criticalCspBySite[$key])) {
            $crit += $criticalCspBySite[$key];
            unset($criticalCspBySite[$key]);
        }
        if (isset($clientErrorsBySite[$key])) {
            $err += $clientErrorsBySite[$key];
            unset($clientErrorsBySite[$key]);
        }
    }

    return ['csp' => $csp, 'criticalCsp' => $crit, 'clientErrors' => $err];
};

foreach ($trafficSites as $domain => $tData) {
    $errCounts = $extractErrorCounts($domain);
    
    // Determine health status based on UNRESOLVED (open) issues
    $health = 'unknown';
    if ($errCounts['criticalCsp'] > 0 || $errCounts['clientErrors'] >= 10) {
        $health = 'critical';
    } elseif ($errCounts['csp'] > 0 || $errCounts['clientErrors'] > 0) {
        $health = 'warning';
    }

    $sitesOverview[] = [
        'domain' => $domain,
        'service' => str_replace('.', '-', $domain),
        'todayViews' => $tData['todayViews'],
        'todayVisits' => $tData['todayVisits'],
        'weekViews' => $tData['weekViews'],
        'weekVisits' => $tData['weekVisits'],
        'monthViews' => $tData['monthViews'],
        'monthVisits' => $tData['monthVisits'],
        'topPages' => $tData['topPages'],
        'cacheStatus' => '🟢 7日保持 (604,800s)',
        'cspCount' => $errCounts['csp'],
        'criticalCsp' => $errCounts['criticalCsp'],
        'clientErrorsCount' => $errCounts['clientErrors'],
        'health' => $health,
    ];
}

$remainingServices = array_unique(array_merge(array_keys($cspCountsBySite), array_keys($clientErrorsBySite)));
foreach ($remainingServices as $svc) {
    if (empty($svc)) continue;
    $csp = $cspCountsBySite[$svc] ?? 0;
    $crit = $criticalCspBySite[$svc] ?? 0;
    $err = $clientErrorsBySite[$svc] ?? 0;
    
    $health = ($crit > 0 || $err >= 10) ? 'critical' : (($csp > 0 || $err > 0) ? 'warning' : 'unknown');

    $sitesOverview[] = [
        'domain' => $svc,
        'service' => $svc,
        'todayViews' => 0,
        'todayVisits' => 0,
        'weekViews' => 0,
        'weekVisits' => 0,
        'monthViews' => 0,
        'monthVisits' => 0,
        'topPages' => [],
        'cacheStatus' => '通常',
        'cspCount' => $csp,
        'criticalCsp' => $crit,
        'clientErrorsCount' => $err,
        'health' => $health,
    ];
}

$totalCsp = (int)($summaryRow['total_reports'] ?? 0);
$totalClientErr = (int)($clientErrSummaryRow['total_client_errors'] ?? 0);

$services = array_values(array_unique(array_map('telemetry_service', $services)));
$allServicesList = array_values(array_unique(array_merge(
    $services,
    array_keys($trafficSites)
)));
sort($allServicesList);

$incidents = telemetry_redact_rows($incidents, false);
$clientErrors = telemetry_redact_rows($clientErrors, true);
try { $collection = telemetry_health($pdo); }
catch (Throwable $e) { $collection = ['state' => 'unavailable', 'lastReceivedAt' => null]; }
if ($collection['state'] === 'unavailable') {
    foreach ($sitesOverview as &$site) $site['health'] = 'unknown';
    unset($site);
}
echo json_encode([
    'status' => $collection['state'] === 'unavailable' ? 'unavailable' : 'ok',
    'collection' => $collection,
    'generatedAt' => gmdate('Y-m-d\TH:i:s\Z'),
    'summary' => [
        'totalReports' => $totalCsp + $totalClientErr,
        'totalCspReports' => $totalCsp,
        'totalClientErrors' => $totalClientErr,
        'uniqueSignatures' => (int)($summaryRow['unique_signatures'] ?? 0) + (int)($clientErrSummaryRow['unique_client_errors'] ?? 0),
        'criticalCount' => (int)($summaryRow['critical_count'] ?? 0),
        'servicesCount' => count($allServicesList),
        'totalTodayViews' => $totalTodayViews,
        'totalWeekViews' => $totalWeekViews,
        'totalMonthViews' => $totalMonthViews,
    ],
    'sitesOverview' => $sitesOverview,
    'services' => $allServicesList,
    'directives' => $directives,
    'dailyTrend' => $dailyTrend,
    'incidents' => $incidents,
    'clientErrors' => $clientErrors
], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
