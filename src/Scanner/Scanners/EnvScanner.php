<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class EnvScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'env';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        $base = $context->basePath;
        $gitignore = $base.'/.gitignore';
        $linesGi = is_file($gitignore) ? $this->readLines($gitignore) : [];
        $envInGitignore = $this->gitignoreMentionsEnv($linesGi);
        if (!$envInGitignore && is_file($base.'/.env')) {
            $issues[] = $this->makeIssue(
                $base.'/.gitignore',
                1,
                Severity::HIGH,
                '`.env` not protected in `.gitignore`',
                'Project has a `.env` file but `.env` is not clearly ignored in `.gitignore`.',
                'Add `.env` and optionally `.env.*` to `.gitignore`. Never commit secrets.',
            );
        }

        $envPath = $base.'/.env';
        if (!is_file($envPath)) {
            if (is_dir($base) && is_file($base.'/composer.json')) {
                $issues[] = $this->makeIssue(
                    $envPath,
                    1,
                    Severity::CRITICAL,
                    '`.env` file missing',
                    'Laravel app root has no `.env` file.',
                    'Copy `.env.example` to `.env` and run `php artisan key:generate`.',
                );
            }
        } else {
            $issues = array_merge($issues, $this->parseEnv($envPath, true, $this->readLines($envPath)));
        }

        $ex = $base.'/.env.example';
        if (is_file($ex)) {
            $lines = $this->readLines($ex);
            $map = $this->parseKeyValuesFromLines($lines);
            if (($map['APP_DEBUG'] ?? null) && $this->truthy($this->stripQuotes($map['APP_DEBUG']))) {
                if (($map['APP_ENV'] ?? 'production') === 'production' || (isset($map['APP_ENV']) && $this->stripQuotes($map['APP_ENV']) === 'production')) {
                    $ln = $this->lineForKey('APP_DEBUG', $lines) ?: 1;
                    $issues[] = $this->makeIssue(
                        $ex,
                        $ln,
                        Severity::CRITICAL,
                        '`APP_DEBUG=true` in `.env.example` for production',
                        '`.env.example` shows APP_DEBUG=true with APP_ENV=production.',
                        'Use `APP_DEBUG=false` in production examples, or document local-only.',
                    );
                }
            }
        }

        return $this->filterSuppressed($this->getKey(), $issues);
    }

    /**
     * @param list<string> $linesGi
     */
    private function gitignoreMentionsEnv(array $linesGi): bool
    {
        foreach ($linesGi as $l) {
            $t = trim(preg_replace('/#.*$/', '', $l) ?? $l);
            if ($t === '' || (isset($t[0]) && $t[0] === '!')) {
                continue;
            }
            if ($t === '.env' || $t === '.env.*' || str_starts_with($t, '.env.')) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param list<string> $lines
     * @return list<\Marlla3x\LaravelShield\Results\Issue>
     */
    private function parseEnv(string $path, bool $isReal, array $lines): array
    {
        $map = $this->parseKeyValuesFromLines($lines);
        $issues = [];

        $appEnv = isset($map['APP_ENV']) ? strtolower($this->stripQuotes($map['APP_ENV'])) : '';
        $appDebug = $map['APP_DEBUG'] ?? null;
        if ($isReal && $appEnv === 'production' && $appDebug !== null && $this->truthy($this->stripQuotes($appDebug))) {
            $ln = $this->lineForKey('APP_DEBUG', $lines) ?: 1;
            $issues[] = $this->makeIssue(
                $path,
                $ln,
                Severity::CRITICAL,
                '`APP_DEBUG=true` in production',
                'APP_ENV is production but APP_DEBUG is enabled.',
                'Set `APP_DEBUG=false` in every production environment.',
            );
        }

        $appKey = $map['APP_KEY'] ?? null;
        if ($isReal) {
            if ($appKey === null || $this->stripQuotes((string) $appKey) === '' || $this->stripQuotes((string) $appKey) === '""' || $this->stripQuotes((string) $appKey) === "''") {
                if ($appEnv === 'production') {
                    $issues[] = $this->makeIssue(
                        $path,
                        max(1, $this->lineForKey('APP_KEY', $lines)),
                        Severity::CRITICAL,
                        '`APP_KEY` empty in production',
                        'APP_ENV is production but APP_KEY is not set.',
                        'Run `php artisan key:generate` and set a strong `APP_KEY`.',
                    );
                } else {
                    $ln = $this->lineForKey('APP_KEY', $lines) ?: 1;
                    if ($appKey === null || $this->stripQuotes((string) $appKey) === '') {
                        $issues[] = $this->makeIssue(
                            $path,
                            $ln,
                            Severity::CRITICAL,
                            '`APP_KEY` missing or empty',
                            'Laravel requires a non-empty `APP_KEY` for encryption and sessions.',
                            'Run `php artisan key:generate`.',
                        );
                    }
                }
            } else {
                $k = $this->stripQuotes((string) $appKey);
                if (str_starts_with($k, 'base64:')) {
                    $raw = (string) @base64_decode(substr($k, 7), true);
                    if (strlen($raw) < 32) {
                        $issues[] = $this->makeIssue(
                            $path,
                            $this->lineForKey('APP_KEY', $lines) ?: 1,
                            Severity::CRITICAL,
                            '`APP_KEY` too short (decoded key)',
                            'Decoded `APP_KEY` is shorter than 32 bytes.',
                            'Regenerate with `php artisan key:generate`.',
                        );
                    }
                } elseif (strlen($k) < 20) {
                    $issues[] = $this->makeIssue(
                        $path,
                        $this->lineForKey('APP_KEY', $lines) ?: 1,
                        Severity::CRITICAL,
                        '`APP_KEY` too short',
                        'The application key is not long enough to be considered secure.',
                        'Use `php artisan key:generate` to set a 32+ byte key.',
                    );
                }
            }
        }

        if ($isReal) {
            $dbPass = $map['DB_PASSWORD'] ?? null;
            if ($dbPass !== null) {
                $dp = strtolower($this->stripQuotes((string) $dbPass));
                if ($dp === '' || in_array($dp, ['root', 'password', 'secret', '12345', 'admin'], true)) {
                    $issues[] = $this->makeIssue(
                        $path,
                        $this->lineForKey('DB_PASSWORD', $lines) ?: 1,
                        Severity::HIGH,
                        'Weak or empty `DB_PASSWORD`',
                        'Database password is empty or a well-known default.',
                        'Set a strong unique password; rotate if this value was ever committed.',
                    );
                }
            }
        }

        foreach ($map as $key => $val) {
            if (! preg_match('/_SECRET$|_KEY$|_TOKEN$/i', (string) $key)) {
                continue;
            }
            if (strcasecmp((string) $key, 'APP_KEY') === 0) {
                continue;
            }
            $v = $this->stripQuotes((string) $val);
            if (in_array(strtolower($v), ['test', 'test123', 'secret', 'dev', 'dev123', 'changeme', 'value', 'key', 'sk_test'], true) || (strlen($v) > 0 && strlen($v) < 8 && ! str_contains((string) $key, 'PUSHER_APP'))) {
                $issues[] = $this->makeIssue(
                    $path,
                    $this->lineForKey($key, $lines) ?: 1,
                    Severity::MEDIUM,
                    'Test-like or weak secret value',
                    "The variable `{$key}` may use a test or default value.",
                    'Use long random values in production; manage secrets with your platform’s secret store.',
                );
            }
        }

        return $issues;
    }

    private function lineForKey(string $key, array $lines): int
    {
        foreach ($lines as $i => $line) {
            if (preg_match('/^\s*'.preg_quote($key, '/').'\s*=/i', $line)) {
                return $i + 1;
            }
        }
        return 0;
    }

    /**
     * @return array<string, string>
     */
    private function parseKeyValuesFromLines(array $lines): array
    {
        $out = [];
        foreach ($lines as $line) {
            if (preg_match('/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/', $line, $m)) {
                $out[$m[1]] = rtrim($m[2], "\r");
            }
        }
        return $out;
    }

    private function truthy(string $s): bool
    {
        return in_array(strtolower($s), ['true', '1', 'yes', 'on'], true);
    }

    private function stripQuotes(string $s): string
    {
        $s = trim($s);
        if (strlen($s) >= 2 && ((str_starts_with($s, '"') && str_ends_with($s, '"')) || (str_starts_with($s, "'") && str_ends_with($s, "'")))) {
            return substr($s, 1, -1);
        }
        return $s;
    }
}
