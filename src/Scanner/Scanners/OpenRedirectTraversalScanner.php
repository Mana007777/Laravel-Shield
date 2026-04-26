<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class OpenRedirectTraversalScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'redirect';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        foreach ($context->allPhpFiles() as $file) {
            $lines = $this->readLines($file);
            foreach ($lines as $i => $line) {
                $n = $i + 1;
                if (preg_match('/^\s*(\/\/|#|\/\*|\*)/', ltrim($line))) {
                    continue;
                }
                if (preg_match('/\b(redirect\(\)|return\s+redirect\(|->redirectTo\()/i', $line)
                    && preg_match('/\$_(GET|REQUEST)|\$request->(input|get|query)\(/i', $line)) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::HIGH,
                        'Potential open redirect using user-controlled target',
                        'Redirect target appears to be built from request input.',
                        'Allow-list redirect destinations or use named internal routes only.',
                    );
                }

                $traversalSink = preg_match('/\b(file_get_contents|fopen|readfile|Storage::(get|put|download)|response\(\)->download)\s*\(/i', $line);
                $taintedPath = preg_match('/\$_(GET|REQUEST)|\$request->(input|get|query)\(/i', $line) || str_contains($line, '..');
                if ($traversalSink && $taintedPath) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::CRITICAL,
                        'Potential path traversal / LFI sink',
                        'File path operation may use user input, enabling directory traversal or local file include exposure.',
                        'Normalize and canonicalize paths, enforce base directory allow-lists, and reject `..` segments.',
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
