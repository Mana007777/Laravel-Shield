<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class ApiSecurityScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'api';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        $issues = array_merge($issues, $this->scanApiRoutes($context));
        $issues = array_merge($issues, $this->scanApiControllers($context));

        return $this->filterSuppressed($this->getKey(), $this->dedupe($issues));
    }

    /**
     * @return list<Issue>
     */
    private function scanApiRoutes(ScanContext $context): array
    {
        $issues = [];
        $apiRoutes = $context->basePath.'/routes/api.php';
        if (!is_file($apiRoutes)) {
            return $issues;
        }

        $lines = $this->readLines($apiRoutes);
        $fileContent = (string) @file_get_contents($apiRoutes);
        $hasGlobalApiThrottle = str_contains($fileContent, 'throttle:api')
            || str_contains($fileContent, 'ThrottleRequests')
            || str_contains($fileContent, "->middleware('throttle")
            || str_contains($fileContent, 'RateLimiter::');

        foreach ($lines as $i => $line) {
            $n = $i + 1;
            if (preg_match('/^\s*(\/\/|#|\/\*|\*)/', ltrim($line))) {
                continue;
            }
            if (preg_match('/Route::(post|put|patch|delete|apiResource|resource)\s*\(/i', $line)) {
                $hasAuth = preg_match('/auth(?::sanctum|:api|:passport)?/i', $line)
                    || str_contains($line, 'middleware([\'auth')
                    || str_contains($line, 'middleware("auth');
                if (!$hasAuth && preg_match('/(admin|user|account|profile|payment|billing|order|cart|wallet|token|settings)/i', $line)) {
                    $issues[] = $this->makeIssue(
                        $apiRoutes,
                        $n,
                        Severity::HIGH,
                        'Sensitive API route without visible auth middleware',
                        'State-changing endpoint appears sensitive but line has no explicit `auth:*` middleware.',
                        'Protect API endpoints using `auth:sanctum` / `auth:api` and authorization policies.',
                    );
                }

                $hasThrottle = preg_match('/throttle(?::\w+)?/i', $line);
                if (!$hasThrottle && !$hasGlobalApiThrottle) {
                    $issues[] = $this->makeIssue(
                        $apiRoutes,
                        $n,
                        Severity::MEDIUM,
                        'API route may be missing rate limiting',
                        'No visible route-level or global API throttling was detected.',
                        'Add `throttle:api` (or custom limiter) to reduce abuse and brute-force risk.',
                    );
                }
            }
        }

        if (!str_contains($fileContent, 'auth:sanctum')
            && !str_contains($fileContent, 'auth:api')
            && !str_contains($fileContent, "middleware('auth")
            && !str_contains($fileContent, 'middleware("auth')) {
            $issues[] = $this->makeIssue(
                $apiRoutes,
                1,
                Severity::MEDIUM,
                'No explicit auth middleware found in routes/api.php',
                'The API route file has no obvious auth middleware usage.',
                'Review route groups and controller constructors to ensure API auth is enforced.',
            );
        }

        return $issues;
    }

    /**
     * @return list<Issue>
     */
    private function scanApiControllers(ScanContext $context): array
    {
        $issues = [];
        $dirs = ['app/Http/Controllers/Api', 'app/Http/Controllers/API', 'app/Http/Controllers'];
        foreach ($dirs as $dir) {
            foreach ($context->findFiles($dir, 'php', true) as $file) {
                if (!str_contains($file, 'Controller')) {
                    continue;
                }
                $lines = $this->readLines($file);
                foreach ($lines as $i => $line) {
                    $n = $i + 1;
                    if (preg_match('/^\s*(\/\/|#|\/\*|\*)/', ltrim($line))) {
                        continue;
                    }
                    if (preg_match('/\$request->(all|get|input|query)\s*\(/i', $line)
                        && !preg_match('/validate\s*\(/i', $line)) {
                        $issues[] = $this->makeIssue(
                            $file,
                            $n,
                            Severity::HIGH,
                            'API request input usage without visible validation',
                            'Controller reads request input directly without inline validation on this line.',
                            'Use FormRequest classes or `$request->validate()` with strict rules per endpoint.',
                        );
                    }
                    if (preg_match('/\b(dd|dump|var_dump)\s*\(/i', $line)) {
                        $issues[] = $this->makeIssue(
                            $file,
                            $n,
                            Severity::MEDIUM,
                            'Debug output in API controller',
                            'Debug calls in API responses may leak internals and secrets.',
                            'Remove debug output and return standardized sanitized error responses.',
                        );
                    }
                    if (preg_match('/->withToken\s*\(|Authorization[\'"]\s*=>\s*[\'"]Bearer/i', $line)) {
                        $issues[] = $this->makeIssue(
                            $file,
                            $n,
                            Severity::INFO,
                            'API token handling detected',
                            'Controller code includes explicit bearer token handling.',
                            'Ensure tokens are short-lived, rotated, and never logged.',
                        );
                    }
                    if (preg_match('/return\s+response\(\s*->json\(\s*\$e->getMessage\(\)/i', $line)
                        || preg_match('/return\s+\$e->getMessage\(/i', $line)) {
                        $issues[] = $this->makeIssue(
                            $file,
                            $n,
                            Severity::HIGH,
                            'Raw exception message returned from API',
                            'Returning internal exception messages can leak stack/database/system details.',
                            'Return generic error messages to clients and log detailed errors server-side only.',
                        );
                    }
                }
            }
        }

        return $issues;
    }

    /**
     * @param list<Issue> $issues
     * @return list<Issue>
     */
    private function dedupe(array $issues): array
    {
        $seen = [];
        $out = [];
        foreach ($issues as $i) {
            $k = $i->file.':'.$i->line.':'.$i->title;
            if (isset($seen[$k])) {
                continue;
            }
            $seen[$k] = true;
            $out[] = $i;
        }
        return $out;
    }
}
