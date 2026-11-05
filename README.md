# zero-pii-telemetry

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](docker-compose.yml)
[![PHP](https://img.shields.io/badge/PHP-8.2%20%7C%208.3-777BB4.svg)]()
[![SQLite](https://img.shields.io/badge/SQLite-WAL-003B57.svg)]()

A lightweight, self-hosted **W3C Content Security Policy (CSP) violation & client-side JavaScript crash collector** with a single-page monitoring dashboard.

Powered exclusively by **PHP and SQLite (WAL mode)** with **zero external daemons, zero tracking, and zero PII stored on disk**.

---

## 💡 Why `zero-pii-telemetry`?

Most engineering teams struggle with CSP and error reporting:
- **Sentry / Datadog Overkill**: Heavyweight, costly, and resource-intensive (self-hosted Sentry requires 10+ Docker containers and 16+ GB RAM).
- **Extension Noise Pollution**: 90%+ of incoming CSP reports are caused by browser extensions (translation tools, ad blockers, password managers) injecting scripts, flooding databases and exhausting SaaS quotas.
- **Privacy & PII Leak Hazards**: User query parameters, authorization tokens, personal email addresses, and DOM values can easily leak into free-form error stack traces and URLs.

`zero-pii-telemetry` solves these problems by design:

1. **Zero-Knowledge (PII-Free) Redaction**:
   Arbitrary stack traces and query strings are never stored. Error messages are normalized into finite standard classes (`TypeError`, `ReferenceError`, etc.), and URLs are strictly allowlisted and path-masked (`https://app.example.com/[redacted]`).
2. **Aggressive Extension Noise Filtering**:
   Automatically discards `chrome-extension://`, `moz-extension://`, and common injected third-party snippets before writing to SQLite.
3. **Atomic Day-Scoped Fingerprint Deduplication**:
   Recurring events update a counter rather than creating millions of identical database rows.
4. **Hardened Storage Boundary**:
   Strictly enforces that the SQLite storage directory (`TELEMETRY_DATA_DIR`) resides **outside** the web server's `DOCUMENT_ROOT`, eliminating accidental database downloads.
5. **Integrated Single-Page Dashboard**:
   Lightweight, clean UI (`src/index.html`) with search, metrics, triage status, and automatic 90-day garbage collection.

---

## 🚀 Quick Start (Docker Compose)

Get up and running in 30 seconds with Docker Compose:

```bash
git clone https://github.com/takaodev/zero-pii-telemetry.git
cd zero-pii-telemetry
docker compose up -d
```

- **Collector Endpoint**: `http://localhost:8080/collector.php`
- **Dashboard UI**: `http://localhost:8080/index.html`

Data is persisted safely in the `telemetry-data` Docker volume.

---

## 🌐 Standalone Installation (Nginx / OpenLiteSpeed / Apache / PHP)

### Prerequisites
- PHP 8.2+ with `pdo_sqlite` and `curl` extensions.
- Writeable private directory outside the document root (e.g., `/var/lib/telemetry`).

### Setup

1. Copy `src/` to your web server document root (e.g., `/var/www/telemetry`).
2. Create the private storage folder outside the web root:
   ```bash
   sudo mkdir -p /var/lib/telemetry
   sudo chown -R www-data:www-data /var/lib/telemetry
   sudo chmod 700 /var/lib/telemetry
   ```
3. Configure environment variables in your web server (`.env`, fastcgi params, or vhost config):
   ```bash
   TELEMETRY_DATA_DIR=/var/lib/telemetry
   TELEMETRY_ALLOWED_HOSTS=example.com,app.example.com
   TELEMETRY_SERVICES=web,api,dashboard
   ```

---

## 📡 Client Configuration

### 1. CSP Header (`Content-Security-Policy`)

Add the report directive to your web server or HTML headers:

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; report-uri https://telemetry.example.com/collector.php;
```

Or using the modern W3C `Reporting-Endpoints` specification:

```http
Reporting-Endpoints: csp-endpoint="https://telemetry.example.com/collector.php"
Content-Security-Policy: default-src 'self'; script-src 'self'; report-to csp-endpoint;
```

### 2. Client-Side JavaScript Crash Reporter

Send uncaught errors without external libraries (~20 lines of code):

```javascript
window.addEventListener('error', (event) => {
  navigator.sendBeacon('/collector.php', JSON.stringify({
    type: 'client-error',
    message: String(event.message || event.error),
    url: window.location.href,
    source: event.filename,
    lineno: event.lineno,
    colno: event.colno,
  }));
});

window.addEventListener('unhandledrejection', (event) => {
  navigator.sendBeacon('/collector.php', JSON.stringify({
    type: 'client-error',
    message: 'UnhandledRejection ' + String(event.reason),
    url: window.location.href,
  }));
});
```

---

## ⚙️ Environment Variables

| Variable | Description | Default |
| --- | --- | --- |
| `TELEMETRY_DATA_DIR` | Absolute path to SQLite storage (must be outside document root) | **Required** |
| `TELEMETRY_ALLOWED_HOSTS` | Comma-separated list of approved domains for URL logging | Host header / localhost |
| `TELEMETRY_SERVICES` | Comma-separated list of recognized service names | `default,web,api,app` |
| `TELEMETRY_ALLOWED_SCREENS` | Comma-separated list of recognized screen/route names | Common defaults |
| `TELEMETRY_REQUESTS_PER_MINUTE` | Global rate limit ceiling per minute | `600` |
| `TELEMETRY_PEER_REQUESTS_PER_MINUTE` | Per-IP rate limit ceiling per minute | `120` |
| `TELEMETRY_MAX_BYTES` | Maximum SQLite database file size before backpressure | `67108864` (64 MB) |
| `TELEMETRY_MAX_ROWS` | Maximum record count before GC or ingestion pause | `100000` |
| `CSP_WEBHOOK_URL` | Optional Slack or Discord incoming webhook for critical alerts | `""` |

---

## 🛡️ Security Architecture

```
Client Browser
     │
     │  POST /collector.php (32 KiB cap, rate-limited)
     ▼
[Collector Guard] ── Drops extension noise (chrome-extension://, adblockers)
     │
[PII Redactor]    ── Normalizes error messages (TypeError, SyntaxError)
     │            ── Masks non-allowlisted origins to [redacted]
     ▼
[SQLite Storage]  ── Enforces outside-document-root path
                  ── Day-scoped fingerprint deduplication
                  ── SQLite WAL mode (high-throughput writes)
```

---

## 📊 CLI Data Export & Reporting

Export aggregated incident records directly to CSV or JSON for compliance reviews or internal analytics:

```bash
# Export last 30 days as JSON
php src/tools/export-telemetry.php --format=json --days=30

# Export last 7 days as CSV to a file
php src/tools/export-telemetry.php --format=csv --days=7 --output=reports/errors.csv

# Export specific service events
php src/tools/export-telemetry.php --type=csp --service=web
```

---

## 📄 License

MIT License © 2026 takaodev
