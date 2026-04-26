<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class IdorScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'idor';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        $issues = array_merge($issues, $this->scanRoutes($context));
        $issues = array_merge($issues, $this->scanControllers($context));

        return $this->filterSuppressed($this->getKey(), $this->dedupe($issues));
    }

    /**
     * @return list<Issue>
     */
    private function scanRoutes(ScanContext $context): array
    {
        $issues = [];
        foreach (['routes/web.php', 'routes/api.php'] as $rel) {
            $path = $context->basePath.'/'.$rel;
            if (!is_file($path)) {
                continue;
            }
            $lines = $this->readLines($path);
            foreach ($lines as $i => $line) {
                $n = $i + 1;
                if (preg_match('/^\s*(\/\/|#|\/\*|\*)/', ltrim($line))) {
                    continue;
                }
                $hasParam = preg_match('/\{(id|user|account|order|invoice|profile|tenant)(\??)\}/i', $line);
                if (!$hasParam) {
                    continue;
                }
                $hasMethod = preg_match('/Route::(get|post|put|patch|delete|resource|apiResource)\s*\(/i', $line);
                if (!$hasMethod) {
                    continue;
                }
                $hasProtection = preg_match('/middleware\(.+?(auth|can:|signed|throttle|scopes?:)/i', $line);
                if (!$hasProtection) {
                    $issues[] = $this->makeIssue(
                        $path,
                        $n,
                        Severity::HIGH,
                        'Potential IDOR-prone route parameter without visible protection',
                        'Route contains direct object identifier-like parameter and no visible auth/authorization middleware.',
                        'Use `auth` + policy/gate checks (`can:` middleware or `$this->authorize`) and avoid exposing predictable IDs.',
                    );
                }
            }
        }
        return $issues;
    }

    /**
     * @return list<Issue>
     */
    private function scanControllers(ScanContext $context): array
    {
        $issues = [];
        foreach ($context->findFiles('app/Http/Controllers', 'php', true) as $file) {
            if (!str_contains($file, 'Controller')) {
                continue;
            }
            $content = (string) @file_get_contents($file);
            if ($content === '') {
                continue;
            }

            if (preg_match_all('/function\s+(show|edit|update|destroy)\s*\([^)]*\)\s*\{([\s\S]{0,2500}?)\n\}/i', $content, $m, PREG_SET_ORDER)) {
                foreach ($m as $fn) {
                    $method = strtolower((string) ($fn[1] ?? ''));
                    $body = (string) ($fn[2] ?? '');
                    $off = strpos($content, (string) $fn[0]);
                    $line = $off === false ? 1 : 1 + substr_count(substr($content, 0, $off), "\n");

                    $loadsById = preg_match('/(find|findOrFail|where)\s*\(\s*\$[a-zA-Z_]\w*/i', $body)
                        || preg_match('/route\s*\(\s*[\'"]\w+[\'"]\s*\)/i', $body);
                    if (!$loadsById) {
                        continue;
                    }

                    $hasAuthz = preg_match('/authorize\s*\(|Gate::|->can\s*\(|middleware\([\'"]can:/i', $body);
                    if (!$hasAuthz) {
                        $issues[] = $this->makeIssue(
                            $file,
                            $line,
                            Severity::HIGH,
                            'Potential IDOR risk in `'.$method.'` action',
                            'Controller action looks up resource by identifier without visible authorization check in method body.',
                            'Add policy authorization (`$this->authorize(...)`) or route middleware (`can:`), and scope queries to the authenticated user/tenant.',
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

