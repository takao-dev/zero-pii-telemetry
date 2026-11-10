# Telemetry hardening / rollout

This change is source-only until the server settings, migration and HTTP acceptance below are completed. Do not deploy it without configuring private storage: collection fails closed with 503 when storage is absent or inside DocumentRoot.

## Management authentication

The management API enforces HTTP Basic authentication itself. Set `TELEMETRY_ADMIN_PASSWORD_HASH` to a PHP `password_hash()` result and optionally `TELEMETRY_ADMIN_USER` (default `admin`); unset/invalid configuration returns503. Open `login.php` to authenticate before using the dashboard. Supply credentials only over TLS or loopback; add proxy rate limits for password attempts. Forward Authorization through FastCGI. No proxy-identity header bypass is supported. Set `PORTAL_MANAGEMENT_ORIGIN` explicitly for triage CSRF protection. Compose maps `TELEMETRY_MANAGEMENT_ORIGIN` to this variable and binds only127.0.0.1 by default. Keep public collector routing separate from private management.

## Configuration

- `PORTAL_TELEMETRY_DATA_DIR`: required absolute directory **outside** the OpenLiteSpeed DocumentRoot. Use a dedicated owner-only directory on a local filesystem, e.g. `/var/lib/portal/telemetry`. Do not share the SQLite file over NFS/SMB. Allow only the intended PHP worker account to access it; keep backups private too.
- `PORTAL_MANAGEMENT_ORIGIN`: exact dashboard Origin, required; no deployment-specific default. Used for triage POST protection; does not replace upstream authentication/ACLs.
- `PORTAL_TELEMETRY_SERVICES`: comma-separated approved service identifiers. Defaults preserve `houkago-link`, `manage-portal`, `unknown`, `other`. Register the identifiers used by the 15 sites before rollout; unknown identifiers/URL hosts become `other` so arbitrary strings cannot enter telemetry through a service-name copy.
- `CSP_WEBHOOK_URL`: optional HTTPS Slack/Discord-compatible webhook. Supply through server environment; the old document-root `config.json` fallback is no longer used. Default allowed hosts: hooks.slack.com, discord.com, discordapp.com. No redirects. Additional approved public origins can be configured with `PORTAL_TELEMETRY_WEBHOOK_ORIGINS`.
- Defaults: `PORTAL_TELEMETRY_REQUESTS_PER_MINUTE=600`, `PORTAL_TELEMETRY_PEER_REQUESTS_PER_MINUTE=120`, `PORTAL_TELEMETRY_MAX_ROWS=100000`, `PORTAL_TELEMETRY_MAX_BYTES=67108864`. Caps cover DB+WAL+SHM at request admission; filesystem quotas are still needed as the hard disk boundary. A full store rejects ingestion with 503 until maintenance/capacity is addressed. Rate rejection uses 429. Observe real traffic before tuning.

The peer key uses REMOTE_ADDR, not user-controlled forwarded headers. With a tunnel/reverse proxy several clients may share one peer budget. Configure the server's trusted-client-IP handling or tune peer/global limits for that topology; do not simply trust X-Forwarded-For in PHP.

## Privacy and status

- Both CSP formats and credentialless browser reports remain supported, including absent/null Origin. Maximum body32KiB and maximum20 CSP items per batch.
- URL paths, credentials, queries, fragments, free-form message text and stacks are not retained. Approved source hosts and finite error/screen/service classes remain. This deliberately sacrifices raw debugging detail to prevent PII/credential persistence. Metrics output also masks historical rows; it does not erase the old database.
- Collection reports `unavailable`, `no_reports`, `observed`, or `capacity_limited`, plus lastReceivedAt. Zero events and a reachable dashboard do not prove service uptime. Continue independent uptime/API monitoring.
- Client errors and critical CSPs can notify. Notifications carry fixed text, not event payloads. Cooldown is recorded only after successful delivery. Actual webhook delivery must be accepted separately with the operator's configured endpoint.

## Offline migration and capacity recovery

1. Stop collectors/writers and status updates. Back up the old database with SQLite backup semantics so committed WAL data is included; never copy only the main file while writers are active.
2. Configure the private directory and all approved service identifiers. With the same PHP runtime/environment used by the app, run `php dash/tools/migrate-telemetry.php /absolute/path/to/old/telemetry.sqlite`. It prepares a sanitized compacted copy and refuses to overwrite an existing destination. The original is retained. A failed staging file must be inspected privately; it is not completion evidence.
3. Check row counts, integrity, privacy and permissions before restarting writers. Legacy raw DB/WAL/SHM, `config.json`, backups, filesystem snapshots and old deployments require a separate retention/removal decision; this script does not delete them.
4. Ensure OpenLiteSpeed denies HTTP access to `dash/data/`, config.json and database/backup files. The bundled rewrite rules are defense in depth; verify the actual server Context/ACL and responses. The PHP built-in test server does not enforce .htaccess.
5. Restart only after the private destination and deployment are accepted. Send a synthetic CSP and client error, confirm receipt, lastReceivedAt, triage and notification. Verify management endpoints remain private; the public reports hostname must route only to the collector, never metrics/triage/data.

Retention cleanup runs on incoming requests at most hourly. For an idle/full store, stop writers and run `php dash/tools/maintain-telemetry.php` with the same private directory. It prunes expired90-day events/7-day cooldowns and compacts/checkpoints before restart. At capacity with only current events, adjust approved capacity or retention policy explicitly; do not silently discard current events. A stopped collector needs scheduled operator maintenance if90-day retention is a hard deadline.

## Tests

`PHP_BINARY=/path/to/php python dash/tests/telemetry_test.py` runs only localhost servers and synthetic temporary databases, including limits, private-path rejection, privacy on storage/output, legacy records, triage, migration and capacity recovery. On an isolated Windows PHP zip set PHP_EXTENSION_DIR to its ext directory; the test harness loads pdo_sqlite with `-n`.

`php -n -d extension=pdo_sqlite dash/tests/notification_test.php` exercises webhook success/failure/cooldown with stubbed transport and performs no network requests. Production authentication/ACLs, filesystem permissions, HTTP rewrite enforcement, browser reports and real notification delivery are separate acceptance checks.
