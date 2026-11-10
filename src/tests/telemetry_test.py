"""Isolated localhost regression tests; uses only synthetic SQLite fixtures."""
import base64
import contextlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PHP = os.environ.get('PHP_BINARY', 'php')
PHP_ARGS = [PHP]
if os.environ.get('PHP_EXTENSION_DIR'):
    PHP_ARGS += ['-n', '-d', 'extension_dir=' + os.environ['PHP_EXTENSION_DIR'], '-d', 'extension=pdo_sqlite']
ADMIN_PASSWORD = 'synthetic-admin-password-not-a-secret'
ADMIN_HASH = subprocess.check_output(PHP_ARGS + ['-r', 'echo password_hash(' + json.dumps(ADMIN_PASSWORD) + ', PASSWORD_DEFAULT);']).decode()
SECRET = 'SYNTHETIC-SENSITIVE-12345'

@contextlib.contextmanager
def database(path):
    db = sqlite3.connect(path)
    try:
        with db:
            yield db
    finally:
        db.close()

@contextlib.contextmanager
def server(**settings):
    with tempfile.TemporaryDirectory(prefix='portal-regression-private-') as private:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        origin = f'http://127.0.0.1:{port}'
        env = dict(os.environ, PORTAL_TELEMETRY_DATA_DIR=private,
                   PORTAL_MANAGEMENT_ORIGIN=origin, CSP_WEBHOOK_URL='', OPERATIONS_DATA_DIR=private,
                   TELEMETRY_ADMIN_USER='admin', TELEMETRY_ADMIN_PASSWORD_HASH=ADMIN_HASH)
        env.update(settings)
        process = subprocess.Popen(PHP_ARGS + ['-d', 'display_errors=0', '-S', f'127.0.0.1:{port}', '-t', str(ROOT)],
                                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('Local PHP server failed to start')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.025)
            yield origin, Path(private)
        finally:
            process.terminate()
            process.wait(timeout=10)

def request(origin, path, payload=None, headers=None, authenticate=True):
    body = json.dumps(payload).encode() if payload is not None else None
    values = {'Content-Type': 'application/json'}
    if authenticate and (path.startswith('api/') or path.startswith('login.php')):
        values['Authorization'] = 'Basic ' + base64.b64encode(('admin:' + ADMIN_PASSWORD).encode()).decode()
    values.update(headers or {})
    req = urllib.request.Request(origin + '/' + path, data=body, headers=values)
    try:
        response = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    return response.status, response.read().decode()

def csp(service='synthetic'):
    return {'csp-report': {'document-uri': 'https://manage.takao.me/people/' + SECRET,
                          'blocked-uri': 'https://host.invalid/' + SECRET + '?token=' + SECRET,
                          'effective-directive': 'script-src', 'disposition': 'report'}}

class TelemetryTests(unittest.TestCase):
    def test_management_authentication_cannot_be_replaced_by_origin_headers(self):
        with server() as (origin, private):
            self.assertEqual(request(origin, 'collector.php', csp(), authenticate=False)[0], 204)
            update = {'type': 'csp', 'id': 1, 'status': 'ignored'}
            forged = {'Origin': origin, 'Sec-Fetch-Site': 'same-origin'}
            self.assertEqual(request(origin, 'api/metrics.php', authenticate=False)[0], 401)
            self.assertEqual(request(origin, 'api/triage.php', update, forged, authenticate=False)[0], 401)
            wrong = {'Authorization': 'Basic ' + base64.b64encode(b'admin:wrong').decode()}
            self.assertEqual(request(origin, 'api/metrics.php', headers=wrong)[0], 401)
            wrong_user = {'Authorization': 'Basic ' + base64.b64encode(('other:' + ADMIN_PASSWORD).encode()).decode()}
            self.assertEqual(request(origin, 'api/metrics.php', headers=wrong_user)[0], 401)
            self.assertEqual(request(origin, 'api/metrics.php')[0], 200)
            self.assertEqual(request(origin, 'api/triage.php', update, {'Origin': origin})[0], 200)
            self.assertEqual(request(origin, 'login.php', authenticate=False)[0], 401)
            self.assertEqual(request(origin, 'login.php')[0], 200)
            with database(private / 'telemetry.sqlite') as db:
                self.assertEqual(db.execute('SELECT status FROM csp_violations').fetchone()[0], 'ignored')

    def test_management_fails_closed_without_a_valid_password_hash(self):
        for configured in ['', 'not-a-password-hash']:
            with self.subTest(configured=configured), server(TELEMETRY_ADMIN_PASSWORD_HASH=configured) as (origin, _):
                self.assertEqual(request(origin, 'collector.php', csp(), authenticate=False)[0], 204)
                self.assertEqual(request(origin, 'api/metrics.php')[0], 503)
                self.assertEqual(request(origin, 'api/triage.php', {'type':'csp','id':1,'status':'ignored'}, {'Origin':origin})[0], 503)

    def test_masks_persistence_and_preserves_deduplication(self):
        with server() as (origin, private):
            self.assertEqual(request(origin, 'collector.php', csp())[0], 204)
            self.assertEqual(request(origin, 'collector.php', csp())[0], 204)
            error = {'type': 'client-error', 'url': 'https://manage.takao.me/' + SECRET + '?token=' + SECRET,
                     'source': 'https://manage.takao.me/assets/' + SECRET, 'message': 'TypeError ' + SECRET,
                     'stack': SECRET, 'lineno': 10}
            self.assertEqual(request(origin, 'collector.php', error)[0], 204)
            with database(private / 'telemetry.sqlite') as db:
                rows = db.execute('SELECT * FROM client_errors').fetchall()
                self.assertNotIn(SECRET, repr(rows))
                self.assertEqual(db.execute('SELECT count FROM csp_violations').fetchone()[0], 2)
                self.assertNotIn(SECRET, repr(db.execute('SELECT * FROM csp_violations').fetchall()))
            status, body = request(origin, 'api/metrics.php')
            self.assertEqual(status, 200)
            self.assertNotIn(SECRET, body)
            self.assertEqual(json.loads(body)['collection']['state'], 'observed')
            self.assertTrue(json.loads(body)['collection']['lastReceivedAt'])

    def test_redacts_legacy_rows_at_read_boundary(self):
        with server() as (origin, private):
            request(origin, 'collector.php', {'type': 'client-error', 'message': 'TypeError'})
            with database(private / 'telemetry.sqlite') as db:
                db.execute('UPDATE client_errors SET service=?,url=?,message=?,source=?,stack=?', [SECRET] * 5)
            self.assertNotIn(SECRET, request(origin, 'api/metrics.php')[1])

    def test_missing_empty_and_corrupt_database_are_not_healthy(self):
        with server() as (origin, private):
            result = json.loads(request(origin, 'api/metrics.php')[1])
            self.assertEqual(result['collection']['state'], 'unavailable')
            request(origin, 'collector.php', csp())
            with database(private / 'telemetry.sqlite') as db:
                db.execute('DELETE FROM csp_violations')
            self.assertEqual(json.loads(request(origin, 'api/metrics.php')[1])['collection']['state'], 'no_reports')
        with server() as (origin, private):
            (private / 'telemetry.sqlite').write_bytes(b'not a database')
            self.assertEqual(json.loads(request(origin, 'api/metrics.php')[1])['status'], 'unavailable')

    def test_rejects_document_root_storage(self):
        with server(PORTAL_TELEMETRY_DATA_DIR=str(ROOT / 'data')) as (origin, _):
            self.assertEqual(request(origin, 'collector.php', csp())[0], 503)
            self.assertEqual(json.loads(request(origin, 'api/metrics.php')[1])['collection']['state'], 'unavailable')

    def test_rate_row_and_size_caps(self):
        with server(PORTAL_TELEMETRY_PEER_REQUESTS_PER_MINUTE='2') as (origin, _):
            self.assertEqual([request(origin, 'collector.php', csp())[0] for _ in range(3)], [204, 204, 429])
        with server(PORTAL_TELEMETRY_MAX_ROWS='1', PORTAL_TELEMETRY_SERVICES='first,second') as (origin, _):
            self.assertEqual(request(origin, 'collector.php?service=first', csp())[0], 204)
            self.assertEqual(request(origin, 'collector.php?service=second', csp())[0], 503)
        with server(PORTAL_TELEMETRY_MAX_BYTES='1') as (origin, _):
            self.assertEqual(request(origin, 'collector.php', csp())[0], 204)
            self.assertEqual(request(origin, 'collector.php', csp())[0], 503)

    def test_atomic_quota_across_concurrent_php_processes(self):
        from concurrent.futures import ThreadPoolExecutor
        with tempfile.TemporaryDirectory(prefix='portal-quota-private-') as private:
            env = dict(os.environ, PORTAL_TELEMETRY_DATA_DIR=private, PORTAL_TELEMETRY_REQUESTS_PER_MINUTE='5')
            code = "require " + json.dumps(str(ROOT / 'telemetry.php')) + "; echo telemetry_admit(telemetry_data_dir()) ? '1' : '0';"
            def admit(_):
                result = subprocess.run(PHP_ARGS + ['-r', code], env=env, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                return result.stdout.decode()
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(admit, range(20)))
            self.assertEqual(results.count('1'), 5)

    def test_bounded_batches_and_invalid_fields(self):
        with server() as (origin, _):
            batch = [{'type': 'csp-violation', 'body': csp()['csp-report']}] * 21
            self.assertEqual(request(origin, 'collector.php', batch)[0], 413)
            self.assertEqual(request(origin, 'collector.php', batch[:2])[0], 204)
            self.assertEqual(request(origin, 'collector.php', {'type': 'client-error', 'message': []})[0], 400)
            self.assertEqual(request(origin, 'collector.php', {'type': 'client-error', 'stack': 'x' * 40000})[0], 413)

    def test_triage_rejects_cross_origin_and_keeps_same_origin_working(self):
        with server() as (origin, _):
            request(origin, 'collector.php', csp())
            update = {'type': 'csp', 'id': 1, 'status': 'resolved'}
            self.assertEqual(request(origin, 'api/triage.php', update)[0], 403)
            self.assertEqual(request(origin, 'api/triage.php', update, {'Origin': 'https://untrusted.invalid'})[0], 403)
            self.assertEqual(request(origin, 'api/triage.php', update, {'Origin': origin})[0], 200)

    def test_url_host_cannot_bypass_redaction_through_service(self):
        with server() as (origin, private):
            self.assertEqual(request(origin, 'collector.php', {'type': 'client-error', 'url': 'https://' + SECRET + '.example/', 'message': 'TypeError'})[0], 204)
            with database(private / 'telemetry.sqlite') as db:
                self.assertEqual(db.execute('SELECT service FROM client_errors').fetchone()[0], 'other')
            self.assertNotIn(SECRET, request(origin, 'api/metrics.php')[1])

    def test_capacity_maintenance_restores_ingestion(self):
        with server(PORTAL_TELEMETRY_MAX_BYTES='131072') as (origin, private):
            request(origin, 'collector.php', {'type': 'client-error', 'message': 'TypeError'})
            with database(private / 'telemetry.sqlite') as db:
                db.execute('UPDATE client_errors SET stack=?,last_seen_at=?', ('x' * 500000, '2000-01-01T00:00:00Z'))
            self.assertEqual(request(origin, 'collector.php', csp())[0], 503)
            self.assertEqual(json.loads(request(origin, 'api/metrics.php')[1])['collection']['state'], 'capacity_limited')
            env = dict(os.environ, PORTAL_TELEMETRY_DATA_DIR=str(private))
            result = subprocess.run(PHP_ARGS + [str(ROOT / 'tools/maintain-telemetry.php')], env=env, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(request(origin, 'collector.php', csp())[0], 204)

    def test_offline_migration_sanitizes_copy_and_preserves_original(self):
        with server() as (origin, private):
            request(origin, 'collector.php', {'type': 'client-error', 'message': 'TypeError'})
            original = private / 'telemetry.sqlite'
            with database(original) as db:
                db.execute('UPDATE client_errors SET message=?,stack=?', (SECRET, SECRET))
            with tempfile.TemporaryDirectory(prefix='portal-migration-private-') as target:
                env = dict(os.environ, PORTAL_TELEMETRY_DATA_DIR=target)
                result = subprocess.run(PHP_ARGS + [str(ROOT / 'tools/migrate-telemetry.php'), str(original)], env=env, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertNotIn(SECRET.encode(), (Path(target) / 'telemetry.sqlite').read_bytes())
                with database(original) as db:
                    self.assertEqual(db.execute('SELECT message FROM client_errors').fetchone()[0], SECRET)

if __name__ == '__main__':
    unittest.main(verbosity=2)
