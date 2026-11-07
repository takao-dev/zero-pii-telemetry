# zero-pii-telemetry

[![codecov](https://codecov.io/gh/takao-dev/zero-pii-telemetry/branch/main/graph/badge.svg)](https://codecov.io/gh/takao-dev/zero-pii-telemetry)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](docker-compose.yml)
[![PHP](https://img.shields.io/badge/PHP-8.2%20%7C%208.3-777BB4.svg)]()
[![SQLite](https://img.shields.io/badge/SQLite-WAL-003B57.svg)]()

> **外部デーモン不要・個人情報ゼロ（Zero-PII）・追跡なし。PHP と SQLite（WALモード）で動作するセルフホスト型 W3C CSP 違反 ＆ クライアント JS クラッシュ収集・分析ダッシュボード。**

[English README is available here](./README.md)

---

## 💡 なぜ `zero-pii-telemetry` なのか？

Web サービスの運用において、CSP 違反やフロントエンドの JS エラー収集には深刻な問題がつきまといます：

1. **Sentry や Datadog の過剰な複雑さと高コスト**:
   セルフホスト版 Sentry は 10 以上のコンテナと 16 GB 以上のメモリを要求し、小規模〜中規模チームには過剰な運用負荷となります。
2. **ブラウザ拡張機能（AdBlock / 翻訳ツール）によるノイズ爆発**:
   受信する CSP レポートの 90% 以上は、ユーザーのブラウザ拡張機能が DOM やスクリプトを勝手に注入したことによる無関係なノイズです。これによりデータベース容量や SaaS クォータが一瞬で枯渇します。
3. **個人情報（PII）の漏洩リスク**:
   生の URL クエリパラメータ、認可トークン、ユーザー名、DOM 内の機密情報が、エラーメッセージやスタックトレースに混入してディスクに保存されてしまうプライバシー侵害の危険性。

`zero-pii-telemetry` はこれらの課題を設計レベルで解消します：

- **ゼロ知識（PII-Free）マスキング**:
  任意のスタックトレースやクエリ文字列は一切保存しません。エラーメッセージは `TypeError`, `ReferenceError` などの定型クラスに正規化され、URL はホワイトリスト方式で許可されたドメインのみ保持し、パス以降は安全に `/[redacted]` でマスキングされます。
- **拡張機能ノイズの自動破棄**:
  `chrome-extension://`, `moz-extension://` および著名なサードパーティ拡張由来の違反レポートを、SQLite に書き込む前に自動でフィルタリングして破棄します。
- **日別フィンガープリントによる重複排除**:
  同一事象の連続発生はカウントアップのみ行い、データベース行数が爆発するのを防ぎます。
- **ドキュメントルート外の強制（Storage Boundary Guard）**:
  SQLite ファイルの保存先ディレクトリ（`TELEMETRY_DATA_DIR`）が Web サーバーの `DOCUMENT_ROOT` 外にあることを起動時に強制検証。万が一の設定ミスによるデータベースファイルの外部直接ダウンロードを物理的に防ぎます。
- **スプレッドシート数式インジェクション（CSV DDE）対策**:
  蓄積されたインシデントを CSV エクスポートする際、悪意ある数式実行文字（`=`, `+`, `-`, `@`）を安全に無力化します。
- **軽量シングルページ管理画面**:
  Vue / React などの重いビルドを必要としない、単一 HTML ファイル（`src/index.html`）による高速ダッシュボードを内蔵。

---

## 🚀 クイックスタート (Docker Compose)

わずか 30 秒で起動できます：

```bash
git clone https://github.com/takao-dev/zero-pii-telemetry.git
cd zero-pii-telemetry
docker compose up -d
```

- **収集エンドポイント**: `http://localhost:8080/collector.php`
- **ダッシュボード画面**: `http://localhost:8080/index.html`

データは `telemetry-data` ボリュームに安全に永続化されます。

---

## 🌐 スタンドアロン設置 (Nginx / OpenLiteSpeed / Apache)

### 前提条件
- PHP 8.2 以上（`pdo_sqlite` および `curl` 拡張）
- ドキュメントルート外の書き込み可能ディレクトリ（例: `/var/lib/telemetry`）

### 設定例（環境変数）

`.env` または Web サーバー設定で指定します：

```ini
TELEMETRY_DATA_DIR=/var/lib/telemetry
TELEMETRY_ALLOWED_HOSTS=app.example.com,api.example.com
TELEMETRY_SERVICES=frontend,admin-portal
CSP_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
```

---

## 📡 クライアントからのレポート送信

### 1. W3C CSP 違反レポートの受信

HTTP レスポンスヘッダーに以下を追加するだけで、ブラウザが自動的に `collector.php` にレポートを送信します：

```http
Content-Security-Policy: default-src 'self'; report-uri /collector.php;
```

### 2. クライアント側 JavaScript 例外のキャプチャ

```javascript
window.addEventListener('error', (event) => {
  navigator.sendBeacon('/collector.php', JSON.stringify({
    type: 'client-error',
    message: event.message,
    source: event.filename,
    lineno: event.lineno,
    colno: event.colno,
    url: window.location.href,
  }));
});
```

---

## 📊 CLI データエクスポートツール

蓄積されたエラーや違反インシデントを、個人情報を含まない安全な形式で CSV または JSON として抽出できます：

```bash
# 過去30日間の記録を JSON 形式で出力
php src/tools/export-telemetry.php --format=json --days=30

# 過去7日間の記録を CSV ファイルとして出力（数式インジェクション対策済み）
php src/tools/export-telemetry.php --format=csv --days=7 --output=reports/errors.csv

# 特定のサービスに絞り込んで出力
php src/tools/export-telemetry.php --type=csp --service=frontend
```

---

## 🛡️ セキュリティアーキテクチャ

```
クライアント（ブラウザ）
     │
     │  POST /collector.php (32 KiB 容量制限, IPレートリミット)
     ▼
[Collector Guard] ── 拡張機能ノイズを破棄 (chrome-extension:// 等)
     │
[PII Redactor]    ── エラー内容を固定クラスに正規化 (TypeError 等)
     │            ── 未承認ドメイン・パスを [redacted] にマスキング
     ▼
[SQLite Storage]  ── ドキュメントルート外の配置を強制
                  ── 日別フィンガープリント重複排除
                  ── 高速な SQLite WAL モード
```

---

## 📄 ライセンス

MIT License © 2026 takao-dev
