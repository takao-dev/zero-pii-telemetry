<?php
declare(strict_types=1);
require_once __DIR__ . '/telemetry.php';
telemetry_require_admin();
header('Location: index.html', true, 303);
exit;
