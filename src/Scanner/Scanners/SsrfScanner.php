<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class SsrfScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'ssrf';
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
                $isHttpSink = preg_match('/\b(Http::(get|post|put|patch|delete|send)|curl_setopt\s*\(|file_get_contents\s*\(|GuzzleHttp\\\\Client->request\s*\()/i', $line);
                if (!$isHttpSink) {
                    continue;
                }
                $hasUrlArg = preg_match('/\b(url|uri|endpoint|target)\b/i', $line)
                    || str_contains($line, 'CURLOPT_URL')
                    || preg_match('/https?:\/\//i', $line)
                    || str_contains($line, '$');
                if (!$hasUrlArg) {
                    continue;
                }
                $tainted = preg_match('/\$_(GET|POST|REQUEST)\b|\$request->(input|get|query|all)\s*\(/i', $line)
                    || preg_match('/\.\s*\$[a-zA-Z_]\w*/', $line);
                $issues[] = $this->makeIssue(
                    $file,
                    $n,
                    $tainted ? Severity::CRITICAL : Severity::HIGH,
                    'Potential SSRF sink with dynamic URL',
                    'HTTP request target may be influenced by runtime/user input.',
                    'Enforce outbound URL allow-lists, block private IP ranges, and canonicalize/validate URLs before requests.',
                );
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
