<?php

namespace YourName\LaravelShield\Scanner\Scanners;

use YourName\LaravelShield\Results\Severity;
use YourName\LaravelShield\ScanContext;
use YourName\LaravelShield\Scanner\BaseScanner;

class DebugScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'debug';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        $base = $context->basePath;
        $appCfg = $base.'/config/app.php';
        if (is_file($appCfg)) {
            $c = (string) file_get_contents($appCfg);
            if (preg_match("/'debug'\\s*=>\\s*true\\s*,/", $c) && !preg_match("/'debug'\\s*=>\\s*env\\s*\\(/", $c)) {
                $issues[] = $this->makeIssue(
                    $appCfg,
                    $this->lineOf($c, "'debug'"),
                    Severity::HIGH,
                    "`config('app.debug')` hard-coded to `true`",
                    '`config/app.php` sets `debug` to the literal `true` instead of `env()`.',
                    "Use `'debug' => (bool) env('APP_DEBUG', false),` so production can disable debug.",
                );
            }
        }

        foreach ($context->allPhpFiles() as $file) {
            if (str_contains($file, DIRECTORY_SEPARATOR.'tests'.DIRECTORY_SEPARATOR)
                || str_contains($file, '/tests/')
                || str_contains($file, '\\tests\\')) {
                continue;
            }
            if (str_contains($file, '/vendor/') || str_contains($file, '\\vendor\\')) {
                continue;
            }
            $dd = 'dd';
            $lines = $this->readLines($file);
            foreach ($lines as $i => $line) {
                $n = $i + 1;
                if (preg_match('/^\s*(\/\/|#|\/\*|\*)/', ltrim($line))) {
                    continue;
                }
                if (preg_match('/\b('.$dd.'|dump|var_dump)\s*\(/', $line)) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::LOW,
                        'Debug helper in application code',
                        'Line may call a dump/abort helper or similar debug output, which can leak data in production.',
                        'Remove before release, or guard with a local environment check only.',
                    );
                }
            }
        }

        $composer = $base.'/composer.json';
        if (is_file($composer)) {
            $json = (string) file_get_contents($composer);
            if (str_contains($json, 'laravel/telescope') || (str_contains($json, 'telescope') && str_contains($json, 'laravel'))) {
                $sp = $base.'/config/telescope.php';
                if (is_file($sp)) {
                    $tc = (string) file_get_contents($sp);
                    if ((str_contains($tc, "'enabled' => true") || str_contains($tc, '"enabled" => true'))
                        && !preg_match("/'enabled'\\s*=>\\s*\\(?\\s*env\\s*\\(/i", $tc)
                        && !str_contains($tc, 'TELESCOPE_ENABLED')) {
                        $issues[] = $this->makeIssue(
                            $sp,
                            1,
                            Severity::MEDIUM,
                            'Laravel Telescope may be always enabled',
                            'Telescope `enabled` is the literal `true` without a clear `env()` gate.',
                            'Use `TELESCOPE_ENABLED` and default it to `false` in production, or `env()` in config.',
                        );
                    }
                }
            }
            if (str_contains($json, 'barryvdh/laravel-debugbar') || (str_contains($json, 'debugbar') && str_contains($json, 'barryvdh'))) {
                $issues[] = $this->makeIssue(
                    $composer,
                    1,
                    Severity::MEDIUM,
                    'Debugbar package is installed',
                    'The dev toolbar is usually disabled via `DEBUGBAR_ENABLED` in production; verify it is not enabled server-side.',
                    'Set `DEBUGBAR_ENABLED=false` in environment config for production, or remove from `require` and use `require-dev` only.',
                );
            }
        }

        return $this->filterSuppressed($this->getKey(), $this->dedupe($issues));
    }

    private function lineOf(string $content, string $needle): int
    {
        $p = stripos($content, $needle);
        if ($p === false) {
            return 1;
        }
        return 1 + substr_count(substr($content, 0, $p), "\n");
    }

    private function dedupe(array $issues): array
    {
        $k = [];
        $o = [];
        foreach ($issues as $i) {
            $s = $i->file.':'.$i->line.':'.$i->title;
            if (isset($k[$s])) {
                continue;
            }
            $k[$s] = true;
            $o[] = $i;
        }
        return $o;
    }
}
