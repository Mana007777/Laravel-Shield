<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

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

        try {
            $issues = [];
            $base = $context->basePath;
            $this->scanAppConfig($base, $issues);
            $this->scanPhpDebugHelpers($context, $issues);
            $this->scanComposerPackages($base, $issues);
            $this->scanTelescopeGate($base, $issues);
            $this->scanTelescopeProviderRegistration($base, $issues);
            $this->scanDebugbarEnv($base, $issues);
            $this->scanExposedDebugRoutes($context, $issues);
            $this->scanBladeAppDebug($context, $issues);

            return $this->filterSuppressed($this->getKey(), $this->dedupe($issues));
        } catch (\Throwable $e) {
            return [
                $this->makeIssue(
                    $context->basePath,
                    1,
                    Severity::MEDIUM,
                    'Debug scanner encountered an error',
                    $e->getMessage(),
                    'Review PHP error logs and re-run the scan.',
                    null,
                    'debug-scanner-error',
                ),
            ];
        }
    }

    /**
     * @param list<\Marlla3x\LaravelShield\Results\Issue> $issues
     */
    private function scanAppConfig(string $base, array &$issues): void
    {
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
                    null,
                    'app-debug-hardcoded',
                );
            }
        }
    }

    private function scanPhpDebugHelpers(ScanContext $context, array &$issues): void
    {
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
                        null,
                        'debug-helper',
                    );
                }
            }
        }
    }

    private function scanComposerPackages(string $base, array &$issues): void
    {
        $composer = $base.'/composer.json';
        if (!is_file($composer)) {
            return;
        }
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
                        null,
                        'telescope-always-on',
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
                null,
                'debugbar-installed',
            );
        }
    }

    private function scanTelescopeGate(string $base, array &$issues): void
    {
        $tsp = $base.'/app/Providers/TelescopeServiceProvider.php';
        if (is_file($tsp)) {
            $tc = (string) file_get_contents($tsp);
            if (preg_match('/function\s+gate\s*\([^)]*\)\s*\{[^}]*return\s+true\s*;/s', $tc)) {
                $issues[] = $this->makeIssue(
                    $tsp,
                    $this->lineOf($tc, 'gate'),
                    Severity::CRITICAL,
                    'Telescope `gate()` allows all users',
                    'The Telescope authorization gate returns `true` unconditionally.',
                    'Restrict Telescope to authorized administrators.',
                    null,
                    'telescope-gate-open',
                );
            }
        }
    }

    /**
     * Flag when Telescope is registered in the app provider list without an obvious local-only guard.
     */
    private function scanTelescopeProviderRegistration(string $base, array &$issues): void
    {
        if (!is_file($base.'/composer.json')) {
            return;
        }
        $cj = (string) file_get_contents($base.'/composer.json');
        if (!str_contains($cj, 'laravel/telescope')) {
            return;
        }
        $candidates = [
            $base.'/bootstrap/providers.php',
            $base.'/config/app.php',
        ];
        foreach ($candidates as $file) {
            if (!is_file($file)) {
                continue;
            }
            $c = (string) file_get_contents($file);
            if (!preg_match('/TelescopeServiceProvider/i', $c)) {
                continue;
            }
            $issues[] = $this->makeIssue(
                $file,
                $this->lineOf($c, 'TelescopeServiceProvider'),
                Severity::HIGH,
                'Telescope provider may load outside local environment',
                'Telescope appears registered without a visible `local` / `APP_ENV` guard in this file.',
                'Register `TelescopeServiceProvider` only when `app()->environment(`local`)` or equivalent.',
                null,
                'telescope-provider-global',
            );
            break;
        }
    }

    private function scanDebugbarEnv(string $base, array &$issues): void
    {
        $envEx = $base.'/.env.example';
        if (is_file($envEx) && preg_match('/^DEBUGBAR_ENABLED\s*=\s*true/m', (string) file_get_contents($envEx))) {
            $issues[] = $this->makeIssue(
                $envEx,
                1,
                Severity::MEDIUM,
                '`DEBUGBAR_ENABLED=true` in `.env.example`',
                'Example env should not encourage enabling debugbar.',
                'Default to `false` and document local-only usage.',
                null,
                'debugbar-env-example',
            );
        }
        $cfg = $base.'/config/debugbar.php';
        if (is_file($cfg)) {
            $c = (string) file_get_contents($cfg);
            if ((str_contains($c, "'enabled' => true") || str_contains($c, '"enabled" => true'))
                && !preg_match("/env\s*\(\s*['\"]DEBUGBAR_ENABLED['\"]/i", $c)) {
                $issues[] = $this->makeIssue(
                    $cfg,
                    1,
                    Severity::HIGH,
                    'Debugbar enabled in config without environment guard',
                    '`enabled` is hard-coded true or lacks DEBUGBAR_ENABLED.',
                    'Gate debugbar with `env(`DEBUGBAR_ENABLED`, false)`.',
                    null,
                    'debugbar-config',
                );
            }
        }
    }

    private function scanExposedDebugRoutes(ScanContext $context, array &$issues): void
    {
        foreach ($context->globProject('routes/*.php') as $rf) {
            $c = (string) file_get_contents($rf);
            if (preg_match('/Route::[^;]+telescope/i', $c) && !preg_match('/middleware\s*\(\s*\[?[^\]]*auth/i', $c)) {
                $issues[] = $this->makeIssue(
                    $rf,
                    1,
                    Severity::HIGH,
                    'Telescope route may lack auth middleware',
                    'Route definitions referencing telescope should be protected.',
                    'Apply `auth` or IP allowlist middleware to `/telescope`.',
                    null,
                    'telescope-route',
                );
            }
            if (preg_match('/Route::[^;]+_debugbar/i', $c) && !preg_match('/middleware\s*\(\s*\[?[^\]]*auth/i', $c)) {
                $issues[] = $this->makeIssue(
                    $rf,
                    1,
                    Severity::MEDIUM,
                    'Debugbar route exposure',
                    'Debugbar routes may be reachable without authentication.',
                    'Disable in production via config and environment.',
                    null,
                    'debugbar-route',
                );
            }
        }
    }

    private function scanBladeAppDebug(ScanContext $context, array &$issues): void
    {
        foreach ($context->allBladeFiles() as $bf) {
            $c = (string) file_get_contents($bf);
            if (preg_match("/config\s*\(\s*['\"]app\.debug['\"]\s*\)/", $c)) {
                $issues[] = $this->makeIssue(
                    $bf,
                    1,
                    Severity::MEDIUM,
                    '`config(`app.debug`)` used in Blade',
                    'Debug flag may be reflected to the frontend or cached views.',
                    'Avoid exposing debug configuration in templates.',
                    null,
                    'blade-app-debug',
                );
            }
        }
    }

    private function lineOf(string $content, string $needle): int
    {
        $p = stripos($content, $needle);
        if ($p === false) {
            return 1;
        }
        return 1 + substr_count(substr($content, 0, $p), "\n");
    }

    /**
     * @param list<\Marlla3x\LaravelShield\Results\Issue> $issues
     * @return list<\Marlla3x\LaravelShield\Results\Issue>
     */
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
