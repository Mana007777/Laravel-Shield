<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;
use Marlla3x\LaravelShield\Util\LaravelKernelMiddlewareExtractor;

class MiddlewareScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'middleware';
    }

    public function scan(ScanContext $context): array
    {
        if (! $context->shouldRun($this->getKey())) {
            return [];
        }

        // Middleware Scanner reports only actionable security findings.
        // Informational middleware inventory is intentionally not emitted as issues.
        $issues = [];
        $base = $context->basePath;
        $kernel = $base.'/app/Http/Kernel.php';

        if (is_file($kernel)) {
            $extracted = LaravelKernelMiddlewareExtractor::extract($kernel);
            if ($extracted !== null) {
                $this->checkKernelSecurity($kernel, $extracted, $issues);
            }
        }

        return $this->filterSuppressed($this->getKey(), $issues);
    }

    /**
     * @param array{global: list<string>, groups: array<string, list<string>>, aliases: array<string, string>, line: int} $extracted
     * @param list<\Marlla3x\LaravelShield\Results\Issue> $issues
     */
    private function checkKernelSecurity(string $kernel, array $extracted, array &$issues): void
    {
        $web = $extracted['groups']['web'] ?? [];
        $webFlat = implode(' ', $web);
        if ($web !== [] && ! $this->stackHasCsrf($webFlat)) {
            $issues[] = $this->makeIssue(
                $kernel,
                $extracted['line'],
                Severity::HIGH,
                '`web` group may be missing CSRF verification',
                'The `web` middleware group does not list `VerifyCsrfToken` / `ValidateCsrfToken` (string match).',
                'Ensure your session-based web stack includes `Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken` or a subclass.',
            );
        }
        $api = $extracted['groups']['api'] ?? [];
        $apiFlat = implode(' ', $api);
        if ($api !== [] && ! preg_match('/[Tt]hrottle(Requests)?|throttle:api|ThrottleApi/i', $apiFlat) && $apiFlat !== '') {
            $issues[] = $this->makeIssue(
                $kernel,
                $extracted['line'],
                Severity::MEDIUM,
                '`api` group may be missing throttling',
                'The `api` group has no obvious `ThrottleRequests` or `throttle:api` entry.',
                'Consider `throttle:api` (or a named limiter) on API routes to reduce abuse.',
            );
        }
    }

    private function stackHasCsrf(string $flat): bool
    {
        return (bool) preg_match('/(VerifyCsrfToken|ValidateCsrfToken|Csrf|csrf)/i', $flat);
    }

    /**
     * @return list<\Marlla3x\LaravelShield\Results\Issue>
     */
    private function scanBootstrapMiddleware(string $bootstrapPath): array
    {
        $c = (string) file_get_contents($bootstrapPath);
        $issues = [];
        if (!str_contains($c, 'withMiddleware')) {
            return $issues;
        }
        $line = 1 + substr_count(substr($c, 0, (int) stripos($c, 'withMiddleware')), "\n");
        $aliases = $this->extractAliasPairsFromString($c);
        if ($aliases !== []) {
            $issues[] = $this->makeIssue(
                $bootstrapPath,
                $line,
                Severity::INFO,
                    'Middleware aliases in `bootstrap/app.php` ('.count($aliases).')',
                $this->truncate($this->formatAliases($aliases)),
                'Laravel 11+ registers `->alias([...])` in the withMiddleware() callback. Prefer named rate limiters in `AppServiceProvider` or `bootstrap/app.php`.',
            );
        }
        $webOps = $this->extractGroupOperations($c, 'web');
        $apiOps = $this->extractGroupOperations($c, 'api');
        if ($webOps !== '') {
            $issues[] = $this->makeIssue(
                $bootstrapPath,
                $line,
                Severity::INFO,
                    '`->web(...)` adjustments in bootstrap',
                $this->truncate($webOps),
                'You can prepend, append, or remove middleware from the `web` group in Laravel 11+.',
            );
        }
        if ($apiOps !== '') {
            $issues[] = $this->makeIssue(
                $bootstrapPath,
                $line,
                Severity::INFO,
                    '`->api(...)` adjustments in bootstrap',
                $this->truncate($apiOps),
                'Common pattern: `api(prepend: [ ... Stateful Sanctum ... ])`.',
            );
        }
        if ($aliases === [] && $webOps === '' && $apiOps === '' && str_contains($c, 'withMiddleware')) {
            $issues[] = $this->makeIssue(
                $bootstrapPath,
                1,
                Severity::INFO,
                '`withMiddleware` present — review callback in file',
                'Check `->web`, `->api`, `->alias`, `->priority`, and any trust/proxy / rate settings in this file.',
                'See the Laravel 11+ middleware section in the framework docs; confirm CSRF and throttling for your use case.',
            );
        }
        return $issues;
    }

    /**
     * @return array<string, string>
     */
    private function extractAliasPairsFromString(string $c): array
    {
        $out = [];
        if (preg_match_all("/['\"]([a-z0-9_:-]+)['\"]\s*=>\s*([\w\\\\]+)::class/si", $c, $m, PREG_SET_ORDER)) {
            foreach ($m as $row) {
                $out[$row[1]] = $row[2].'::class';
            }
        }
        return $out;
    }

    private function extractGroupOperations(string $c, string $g): string
    {
        if (! preg_match("/->".$g."\\s*\\(([\s\\S]{0,1200}?)\)\s*;/U", $c, $m)) {
            return '';
        }
        $inner = (string) ($m[1] ?? '');
        $t = trim(preg_replace("/\s+/", ' ', $inner) ?? $inner);
        if (strlen($t) > 500) {
            $t = substr($t, 0, 497).'...';
        }
        return $t;
    }

    /**
     * @return list<\Marlla3x\LaravelShield\Results\Issue>
     */
    private function listCustomMiddlewareClasses(ScanContext $context): array
    {
        $issues = [];
        $dir = $context->basePath.'/app/Http/Middleware';
        if (!is_dir($dir)) {
            return $issues;
        }
        $files = array_values(array_filter(
            glob($dir.'/*.php') ?: [],
            static fn (string $f) => strcasecmp(basename($f, '.php'), 'Kernel') !== 0
        ));
        $rest = 0;
        if (count($files) > 40) {
            $rest = count($files) - 40;
            $files = array_slice($files, 0, 40);
        }
        foreach ($files as $f) {
            $bn = basename($f, '.php');
            $content = (string) @file_get_contents($f);
            if (preg_match('/namespace\s+([^;]+);/s', $content, $n) && preg_match('/class\s+(\w+)\s+/s', $content, $cl)) {
                $fq = trim($n[1]).'\\'.$cl[1];
            } else {
                $fq = 'App\\Http\\Middleware\\'.$bn;
            }
            $issues[] = $this->makeIssue(
                $f,
                1,
                Severity::INFO,
                'Custom HTTP middleware: `'.$bn.'`',
                'Class: `'.$this->truncate($fq, 200).'`. Review `handle($request, $next)` for auth, redirects, and header policies.',
                'Ensure this middleware is registered (alias, route, or group) and does not log secrets.',
            );
        }
        if ($rest > 0) {
            $issues[] = $this->makeIssue(
                $dir,
                1,
                Severity::INFO,
                'Additional custom middleware files not listed',
                (string) $rest.' more file(s) in `app/Http/Middleware` beyond the 40 shown above.',
                'Run `ls -1 app/Http/Middleware` and review each `handle` method.',
            );
        }
        return $issues;
    }

    /**
     * @return list<\Marlla3x\LaravelShield\Results\Issue>
     */
    private function scanRouteMiddlewareUsage(ScanContext $context): array
    {
        $issues = [];
        $routeDir = $context->basePath.'/routes';
        if (!is_dir($routeDir)) {
            return $issues;
        }
        $counts = [];
        foreach (glob($routeDir.'/*.php') ?: [] as $rfile) {
            $c = (string) file_get_contents($rfile);
            if (preg_match_all("/->middleware\\s*\\(\s*([^)]+)\)/i", $c, $m)) {
                foreach ($m[1] as $raw) {
                    $parts = preg_split("/[',\"]+|,\s*|\[|\]|\s+/", trim($raw, " \t\n\r\0\x0B[]")) ?: [];
                    foreach ($parts as $p) {
                        $p = trim($p, " \t'\"");
                        if ($p === '' || str_contains($p, '::class')) {
                            if (str_contains($p, '::class')) {
                                $k = 'class:'.preg_replace('/\s+/', '', $p);
                                $counts[$k] = ($counts[$k] ?? 0) + 1;
                            }
                            continue;
                        }
                        if (preg_match('/^\w[:\w-]*$/', $p)) {
                            $counts[$p] = ($counts[$p] ?? 0) + 1;
                        }
                    }
                }
            }
            if (preg_match_all("/Route::middleware\\s*\\(\s*([^)]+)\)/i", $c, $m2)) {
                foreach ($m2[1] as $raw) {
                    if (preg_match("/['\"]([a-z0-9:_-]+)['\"]/i", $raw, $mm)) {
                        $a = $mm[1];
                        $counts['group:'.$a] = ($counts['group:'.$a] ?? 0) + 1;
                    }
                }
            }
        }
        if ($counts === []) {
            $issues[] = $this->makeIssue(
                $routeDir,
                1,
                Severity::INFO,
                'No `->middleware()` in `routes/*.php` (or only dynamic patterns)',
                'All middleware may be applied in `RouteServiceProvider` or via controller constructors.',
                'Run `php artisan route:list -v` to see middleware columns.',
            );
            return $issues;
        }
        arsort($counts);
        $summary = [];
        $i = 0;
        foreach ($counts as $k => $n) {
            if ($i++ > 30) {
                $summary[] = '…';
                break;
            }
            $summary[] = $k.': '.$n.'×';
        }
        $firstRoute = (glob($routeDir.'/*.php') ?: [])[0] ?? $routeDir.'/routes.php';
        $issues[] = $this->makeIssue(
            is_file($firstRoute) ? $firstRoute : $routeDir,
            1,
            Severity::INFO,
            'Route-level middleware name usage (from `routes/*.php`)',
            $this->truncate(implode(', ', $summary), 2000),
            'Cross-check with `php artisan route:list` and with Kernel/bootstrap aliases. Unknown strings may be typos.',
        );
        return $issues;
    }

    /**
     * @param list<string> $list
     */
    private function formatList(array $list): string
    {
        if ($list === []) {
            return '(empty)';
        }
        return implode(', ', $list);
    }

    /**
     * @param array<string, string> $aliases
     */
    private function formatAliases(array $aliases): string
    {
        if ($aliases === []) {
            return '(none)';
        }
        $i = [];
        foreach ($aliases as $a => $c) {
            $i[] = $a.' => '.$c;
        }
        return implode(', ', $i);
    }

    private function truncate(string $s, int $max = 1000): string
    {
        if (mb_strlen($s) <= $max) {
            return $s;
        }
        return mb_substr($s, 0, $max - 1).'…';
    }
}
