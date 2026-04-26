# marlla3x / laravel-shield

Security scanner for **Laravel** projects: CLI tool (standalone or `php artisan`) to find common misconfigurations, missing validation, SQL/XSS/CSRF risks, dependency concerns, and debug leftovers. PHP **8.1+**, **Laravel 10/11/12/13** (optional; the binary works on any app tree), **Symfony 6/7/8**. MIT license.

## Compatibilityy

- PHP: `^8.1`
- Laravel Illuminate components: `^10.0|^11.0|^12.0|^13.0`
- Symfony components: `symfony/console` and `symfony/process` `^6.0|^7.0|^8.0`
- Works as:
  - Artisan command inside Laravel apps (`php artisan shield:scan`)
  - standalone binary (`vendor/bin/laravel-shield`)

## Installation

**Per project (recommended)**

```bash
composer require marlla3x/laravel-shield:^1.0 --dev
```

If you are testing before tagging a stable release, use:

```bash
composer require marlla3x/laravel-shield:dev-main --dev
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

Common workflows:

```bash
# Focus on high-risk items first
php artisan shield:scan --severity=high --fix-hints

# Emit JSON report for CI artifacts or PR review
php artisan shield:scan --format=json --output=shield-report.json

# Fail CI when issues remain after filters
php artisan shield:scan --ci --severity=high
```

## Scanners (what they check)

| Key | What it does |
|-----|----------------|
| `env` | `.env` / `.env.example`: `APP_DEBUG` in production, weak `DB_PASSWORD`, short/missing `APP_KEY`, test-like secrets, `.env` not in `.gitignore` |
| `validation` | Controllers: `Request` with `input`/`get`/`all` and no `validate` / FormRequest on resource-like actions |
| `sql` | `DB::…` with concatenation, `*Raw()` with `$` and no `?` bindings, `unprepared` |
| `rce` | Command execution sinks: `exec`, `system`, `shell_exec`, `passthru`, `proc_open`, `popen`, backticks; escalates if dynamic/user input appears |
| `ssrf` | Dynamic outbound request targets in `Http::get/post`, `curl_setopt(CURLOPT_URL, ...)`, `file_get_contents($url)` style sinks |
| `deserialize` | `unserialize()` usage, especially with request/cookie input (object injection risk) |
| `upload` | Upload sinks (`move`, `store`, `putFile`, `move_uploaded_file`) with weak/no visible validation patterns |
| `secrets` | Hardcoded secret patterns (live tokens, AWS-like keys, private key blocks, suspicious credential literals) |
| `cors` | Permissive CORS config (`allowed_origins=*`, credentials with broad origins) and manual wildcard CORS headers |
| `redirect` | Open redirect and path traversal/LFI-style file sinks fed by request input |
| `crypto` | Weak hashes (`md5`, `sha1`), weak cipher/modes, insecure RNG (`rand`/`mt_rand`) in token contexts |
| `jwt` | JWT misconfig patterns (none/verify disabled, weak claim-validation visibility) |
| `api` | API-focused checks on `routes/api.php` and API controllers: missing auth/throttle, direct input without validation, debug/error leakage, token-handling visibility |
| `session` | Session/cookie hardening checks (`secure`, `http_only`, `same_site`) and weak manual cookie flags |
| `headers` | Security-header coverage checks (HSTS, X-Content-Type-Options, CSP, frame/referrer policy) and weak header values |
| `idor` | BOLA/IDOR heuristics: identifier route params and controller resource lookups without visible authorization checks |
| `exposure` | Public web-root exposure checks: `.env`, `.git`, backup/debug artifacts, and executable PHP in upload/storage paths |
| `csrf` | `VerifyCsrfToken` disabled on a route, non-empty CSRF `except` list, HTML forms (POST/PUT/…) missing `@csrf` / `_token` |
| `mass` | Eloquent: `public $guarded = []`, empty `protected $guarded`, or model with no `fillable` / `guarded` |
| `auth` | Routes whose path looks like admin/dashboard and no obvious `auth` middleware on the line; controllers `store`/`update`/… with no `authorize` |
| `middleware` | Reads `app/Http/Kernel.php` (global stack, `web` / `api` groups, route aliases), `bootstrap/app.php` (Laravel 11+), lists `app/Http/Middleware/*`, and aggregates `->middleware()` usage in `routes/*.php`. Flags `web` without CSRF / `api` without obvious throttle. Use `--only=middleware` or `mw` |
| `xss` | Blade `{!! … !!}` with variables, dangerous `echo` of request in views |
| `dependency` | Missing `composer.lock` info, `composer audit` (JSON), a few Packagist `abandoned` checks (network, capped) |
| `debug` | `config('app.debug')` hard-coded, `dd`/`dump` outside tests, Telescope/Debugbar config hints |

Suppress a line: put `// shield:ignore: env` (or `all`) on the line above the finding, or use `php artisan shield:ignore <file> <line> [scanner]`.

For Blade files, you can also use Blade comments:

```blade
{{-- shield:ignore: xss --}}
```

Use ignores only after manual review.

## Configuration

After publishing, edit `config/shield.php` for default `path` and `exclude` lists. The Artisan command merges `shield.exclude` with `--exclude` when you pass extra paths.

## CI/CD (GitHub Actions)

See [`docs/github-actions-example.yml`](docs/github-actions-example.yml). Typical job: `composer install`, `vendor/bin/laravel-shield --ci` (or with `--format=json` and `--output`).

## Troubleshooting

- `Could not find a version ... matching your minimum-stability`:
  - install a tagged release like `^1.0`, or explicitly use `dev-main`.
- Laravel version conflict during install:
  - ensure your app dependencies are compatible with your Laravel major version (`composer why-not laravel/framework ^13.0` is useful).
- Symfony lock-file conflict during install:
  - if Composer reports a partial update conflict, run `composer require marlla3x/laravel-shield:^1.0 --dev -W` to allow dependency graph resolution.
- `--ci` fails on local `.env` values:
  - expected for weak local development secrets; either set secure env vars in CI or lower severity threshold for that pipeline.

## Contributing

- Install dependencies: `composer install`
- Run tests: `vendor/bin/phpunit`
- PSR-12 / consistent style; keep changes focused; add tests for new rules.

## Security policy

If you find a **security issue in this package**, please report it **privately** to the maintainers (see `composer.json` `authors` email) or your org’s process. **Do not** file critical vulnerabilities as public issues until a fix is released.

---

*Packagist: connect your GitHub repo to `https://packagist.org` and register `marlla3x/laravel-shield`. Tag releases, e.g. `git tag v1.0.0 && git push --tags`.*
