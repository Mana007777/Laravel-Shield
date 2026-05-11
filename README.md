# marlla3x / laravel-shield

Security scanner for **Laravel** projects: CLI tool (standalone or `php artisan`) to find common misconfigurations, missing validation, SQL/XSS/CSRF risks, dependency concerns, and debug leftovers. PHP **8.1+**, **Laravel 10/11/12/13** (optional; the binary works on any app tree), **Symfony 6/7/8**. MIT license.

## Compatibility

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

- `--format=table` (default) | `json` | `summary` | `github` — GitHub Actions workflow commands and optional job summary (`$GITHUB_STEP_SUMMARY`)
- `--severity=high` — only report that severity and above
- `--only=env,sql` — run selected scanners (e.g. `--only=livewire,auth,idor`)
- `--exclude=node_modules` — *replace* the default exclude list when you pass a non-empty value (or extend via `config/shield.php` in Laravel)
- `--fix-hints` — print short remediation text per finding
- `--ci` — exit code `1` if any issue remains after filters (with `--diff`, only **new** findings vs baseline fail the job when a baseline exists)
- `--output=report.json` — also write a JSON report
- `--watch` — poll the tree every 2s (rough “watch” mode)
- `--no-score` — hide the 0–100 score line
- `--diff` — report only findings not present in the saved baseline (`shield:baseline`)
- `--breakdown` — per-file risk table; use `--top=N` (default 10) for the riskiest files. With `--format=json`, output includes a `breakdown` object
- `--fix` / `--dry-run` — safe auto-fixes (see below); `--dry-run` previews changes without writing
- `--no-entropy` / `--entropy-threshold=4.5` — tune Shannon-entropy secret heuristics in the `secrets` scanner
- `--all-projects` — scan every path in `config/shield.php` `projects` (monorepo)
- `--interactive` / `-i` — after the scan, open the interactive finding browser
- `--update-hints` — run `composer outdated` major-version lag hints (dependency scanner)
- Files listed in `.gitignore` and `.shieldignore` are skipped by default and are not scanned/counting in findings.
- In GitHub Actions (`GITHUB_ACTIONS=true`), the default format becomes `github` unless you set another `--format`. Set `DISABLE_SHIELD_GITHUB_ANNOTATIONS=1` to keep table output.

### Auto-fix (`--fix`)

Mechanical, reversible patches (originals copied under `.shield-backup/` mirroring paths):

- Ensure `.env` is listed in `.gitignore`
- Insert `@csrf` on Blade opening tags for `POST`/`PUT`/`PATCH`/`DELETE` forms missing `@csrf` / `_token` (per form)
- Replace `md5(` / `sha1(` with `hash('sha256', …)` in non-test PHP (comment `// shield:auto-fixed`)
- Add `secure` and `httponly` to simple one-line `setcookie(` calls that lack them
- Set `APP_DEBUG=false` in `.env.example` when it was `true`

Restore backups: `php artisan shield:fix-restore` (project root).

### Baseline and diff

```bash
php artisan shield:baseline
php artisan shield:scan --diff
```

Findings are hashed as `[scanner, relative file, line, rule]`. Laravel apps store the baseline at `storage/shield-baseline.json`; standalone trees use `.shield-baseline.json` in the project root. If no baseline exists, `--diff` prints a warning and shows the full scan.

When you run with `--diff`, both the scanner counts and the security score are calculated from **new findings only** (findings not present in baseline).  
That means a project can show `Security score: 100/100` in `--diff` mode when there are no new findings, even if a full scan (without `--diff`) still reports existing issues.

### Config drift (`shield:config-diff`)

```bash
php artisan shield:config-diff
```

Compares `config/session.php`, `config/auth.php`, `config/cors.php`, `config/hashing.php`, `config/sanctum.php`, and `config/logging.php` against hardening expectations (session `secure` / `same_site` / `lifetime`, password reset expiry, CORS wildcard + credentials, bcrypt rounds, Argon memory, Sanctum `stateful` breadth, Slack logging without a strict level cap).

### Audit log (`shield:audit-log`)

Each scan appends a JSON line to `storage/shield-audit.jsonl` (or `.shield-audit.jsonl` outside Laravel): timestamp, git short SHA, counts by severity, score, flags, and fix stats.

```bash
php artisan shield:audit-log --since=7d
```

Trend arrows compare each run to the **chronologically previous** run in the table (newest rows first).

### Interactive mode (`-i`)

Arrow keys or j/k to move, Enter to expand (snippet, risk, fix), `f` appends a false-positive line to `.shieldignore`, `x` inserts a `shield:ignore` comment in the source, `s` saves JSON, `q` quits.

### Published config (`config/shield.php`)

- `entropy_threshold`, `max_entropy_file_bytes` (default 512000)
- `projects` — map of label => path for `--all-projects`
- `exclude`, `path`, `watch_interval`, `min_severity` (via CLI)

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
| `validation` | Controllers and Livewire components: request/input handling and state-changing actions with no visible `validate()`/FormRequest |
| `livewire` | Livewire-specific checks: mutable sensitive public props (without `#[Locked]`), state-changing actions without visible authorization, risky upload usage |
| `sql` | `DB::…` with concatenation, `*Raw()` with `$` and no `?` bindings, `unprepared` |
| `rce` | Command execution sinks: `exec`, `system`, `shell_exec`, `passthru`, `proc_open`, `popen`, backticks; escalates if dynamic/user input appears |
| `ssrf` | Dynamic outbound request targets in `Http::get/post`, `curl_setopt(CURLOPT_URL, ...)`, `file_get_contents($url)` style sinks |
| `deserialize` | `unserialize()` usage, especially with request/cookie input (object injection risk) |
| `upload` | Upload sinks (`move`, `store`, `putFile`, `move_uploaded_file`) with weak/no visible validation patterns |
| `secrets` | Hardcoded secret patterns; Shannon entropy on long literals (skipped under `--no-entropy`, for files under `max_entropy_file_bytes`, excluding vendor, migrations, tests, `*.lock`) |
| `cors` | Permissive CORS config (`allowed_origins=*`, credentials with broad origins) and manual wildcard CORS headers |
| `redirect` | Open redirect and path traversal/LFI-style file sinks fed by request input |
| `crypto` | Weak hashes (`md5`, `sha1`), weak cipher/modes, insecure RNG (`rand`/`mt_rand`) in token contexts |
| `jwt` | JWT misconfig patterns (none/verify disabled, weak claim-validation visibility) |
| `api` | API-focused checks on `routes/api.php` and API controllers: missing auth/throttle, direct input without validation, auth bypass patterns, weak credential handling, debug/error leakage, token-handling visibility |
| `session` | Session/cookie hardening checks (`secure`, `http_only`, `same_site`, cookie driver usage, long-lived session config) and weak manual cookie flags |
| `headers` | Security-header coverage checks (HSTS, X-Content-Type-Options, CSP, frame/referrer policy) and weak header values |
| `idor` | BOLA/IDOR heuristics: identifier route params and controller resource lookups without visible authorization checks |
| `exposure` | Recursive public web-root exposure checks: `.env`, `.git`, backup/debug/log artifacts, debug probe files, and executable PHP in upload/storage paths |
| `csrf` | `VerifyCsrfToken` disabled on a route, non-empty CSRF `except` list, HTML forms (POST/PUT/…) missing `@csrf` / `_token` |
| `mass` | Eloquent: `public $guarded = []`, empty `protected $guarded`, or model with no `fillable` / `guarded` |
| `auth` | Routes whose path looks like admin/dashboard and no obvious `auth` middleware on the line; controllers `store`/`update`/… with no `authorize` |
| `middleware` | Reads `app/Http/Kernel.php` (global stack, `web` / `api` groups, route aliases), `bootstrap/app.php` (Laravel 11+), lists `app/Http/Middleware/*`, and aggregates `->middleware()` usage in `routes/*.php`. Flags `web` without CSRF / `api` without obvious throttle. Use `--only=middleware` or `mw` |
| `xss` | Blade `{!! … !!}` with variables, dangerous `echo` of request in views |
| `dependency` | `composer audit` (enriched titles: severity, CVE, affected range, advisory link, fixed-version hint), `composer.lock` tracked check, `minimum-stability: dev` without `prefer-stable`, optional `--update-hints` (`composer outdated` major lag), Packagist abandoned sampling |
| `debug` | `config('app.debug')` hard-coded, `dd`/`dump` outside tests, Telescope service provider registration / gate no-op, Debugbar env and config guards, `/telescope` and `/_debugbar` route middleware heuristics, `config('app.debug')` in Blade |
| `livewire` | Public sensitive props, mutating actions / `wire:click` without authorization, uploads, Volt `state`/`computed` + `auth()->user()`, `#[Computed]` / `#[On]` heuristics, sensitive `wire:model`, `dispatch`/`emit` with sensitive payloads |

Suppress a line: put `// shield:ignore: env` (or `all`) on the line above the finding, or use `php artisan shield:ignore <file> <line> [scanner]`.

For Blade files, you can also use Blade comments:

```blade
{{-- shield:ignore: xss --}}
```

Use ignores only after manual review.

Each finding includes a **risk** statement in table and JSON outputs to help prioritize remediation in CI and code review.

## Configuration

After publishing, edit `config/shield.php` for default `path`, `exclude`, `entropy_threshold`, `max_entropy_file_bytes`, `projects` (monorepo), and `watch_interval`. The Artisan command merges `shield.exclude` with `--exclude` when you pass extra paths.

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
