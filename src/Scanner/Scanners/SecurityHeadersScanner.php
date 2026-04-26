<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class SecurityHeadersScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'headers';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        $middlewareDir = $context->basePath.'/app/Http/Middleware';
        $allContent = '';

        foreach ($context->findFiles('app/Http/Middleware', 'php', true) as $file) {
            $content = (string) @file_get_contents($file);
            $allContent .= "\n".$content;
            $lines = $this->readLines($file);
            foreach ($lines as $i => $line) {
                if (preg_match('/^\s*(\/\/|#|\/\*|\*)/', ltrim($line))) {
                    continue;
                }
                if (preg_match('/->header\s*\(\s*[\'"]X-Frame-Options[\'"]\s*,\s*[\'"]ALLOWALL[\'"]/i', $line)) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $i + 1,
                        Severity::HIGH,
                        'Weak clickjacking protection header',
                        'X-Frame-Options appears overly permissive.',
                        'Use `DENY` or `SAMEORIGIN` and enforce with CSP frame-ancestors.',
                    );
                }
                if (preg_match('/->header\s*\(\s*[\'"]Content-Security-Policy[\'"]\s*,\s*[\'"][^\'"]*unsafe-inline/i', $line)) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $i + 1,
                        Severity::MEDIUM,
                        'CSP allows unsafe-inline',
                        'Unsafe inline scripts/styles reduce CSP effectiveness.',
                        'Adopt nonce/hash-based CSP and remove `unsafe-inline` where possible.',
                    );
                }
            }
        }

        if ($middlewareDir !== '' && is_dir($middlewareDir)) {
            $expected = [
                'Strict-Transport-Security',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'Content-Security-Policy',
                'Referrer-Policy',
            ];
            foreach ($expected as $h) {
                if (!str_contains($allContent, $h)) {
                    $issues[] = $this->makeIssue(
                        $middlewareDir,
                        1,
                        Severity::INFO,
                        'Security header not found: '.$h,
                        'No obvious middleware code sets this response header.',
                        'Consider a centralized security-headers middleware for web/API responses.',
                    );
                }
            }
        }

        return $this->filterSuppressed($this->getKey(), $this->dedupe($issues));
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

