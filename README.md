# marlla3x / laravel-shield

Security scanner for **Laravel** projects: CLI tool (standalone or `php artisan`) to find common misconfigurations, missing validation, SQL/XSS/CSRF risks, dependency concerns, and debug leftovers. PHP **8.1+**, **Laravel 10/11** (optional; the binary works on any app tree). MIT license.

## Installation

**Per project (recommended)**

```bash
composer require marlla3x/laravel-shield --dev
```

Laravel will auto-discover the service provider. Publish config (optional):

```bash
php artisan vendor:publish --tag=shield-config
```

**Global (Composer)**

```bash
composer global require marlla3x/laravel-shield
# Ensure ~/.composer/vendor/bin (or your global Composer path) is on your PATH
laravel-shield
```

**From this repo’s root**

```bash
composer install
./bin/laravel-shield
```

## Quick start

```bash
# From your Laravel app root
vendor/bin/laravel-shield
# or
php artisan shield:scan
```

Useful flags:

- `--format=table` (default) | `json` | `summary`
- `--severity=high` — only report that severity and above
- `--only=env,sql` — run selected scanners
- `--exclude=node_modules` — *replace* the default exclude list when you pass a non-empty value (or extend via `config/shield.php` in Laravel)
- `--fix-hints` — print short remediation text per finding
- `--ci` — exit code `1` if any issue remains after filters
- `--output=report.json` — also write a JSON report
- `--watch` — poll the tree every 2s (rough “watch” mode)
- `--no-score` — hide the 0–100 score line

## Scanners (what they check)

| Key | What it does |
|-----|----------------|
| `env` | `.env` / `.env.example`: `APP_DEBUG` in production, weak `DB_PASSWORD`, short/missing `APP_KEY`, test-like secrets, `.env` not in `.gitignore` |
| `validation` | Controllers: `Request` with `input`/`get`/`all` and no `validate` / FormRequest on resource-like actions |
| `sql` | `DB::…` with concatenation, `*Raw()` with `$` and no `?` bindings, `unprepared` |
| `csrf` | `VerifyCsrfToken` disabled on a route, non-empty CSRF `except` list, HTML forms (POST/PUT/…) missing `@csrf` / `_token` |
| `mass` | Eloquent: `public $guarded = []`, empty `protected $guarded`, or model with no `fillable` / `guarded` |
| `auth` | Routes whose path looks like admin/dashboard and no obvious `auth` middleware on the line; controllers `store`/`update`/… with no `authorize` |
| `middleware` | Reads `app/Http/Kernel.php` (global stack, `web` / `api` groups, route aliases), `bootstrap/app.php` (Laravel 11+), lists `app/Http/Middleware/*`, and aggregates `->middleware()` usage in `routes/*.php`. Flags `web` without CSRF / `api` without obvious throttle. Use `--only=middleware` or `mw` |
| `xss` | Blade `{!! … !!}` with variables, dangerous `echo` of request in views |
| `dependency` | Missing `composer.lock` info, `composer audit` (JSON), a few Packagist `abandoned` checks (network, capped) |
| `debug` | `config('app.debug')` hard-coded, `dd`/`dump` outside tests, Telescope/Debugbar config hints |

Suppress a line: put `// shield:ignore: env` (or `all`) on the line above the finding, or use `php artisan shield:ignore <file> <line> [scanner]`.

## Configuration

After publishing, edit `config/shield.php` for default `path` and `exclude` lists. The Artisan command merges `shield.exclude` with `--exclude` when you pass extra paths.

## CI/CD (GitHub Actions)

See [`docs/github-actions-example.yml`](docs/github-actions-example.yml). Typical job: `composer install`, `vendor/bin/laravel-shield --ci` (or with `--format=json` and `--output`).

## Contributing

- Install dependencies: `composer install`
- Run tests: `vendor/bin/phpunit`
- PSR-12 / consistent style; keep changes focused; add tests for new rules.

## Security policy

If you find a **security issue in this package**, please report it **privately** to the maintainers (see `composer.json` `authors` email) or your org’s process. **Do not** file critical vulnerabilities as public issues until a fix is released.

---

*Packagist: connect your GitHub repo to `https://packagist.org` and register `marlla3x/laravel-shield`. Tag releases, e.g. `git tag v1.0.0 && git push --tags`.*
