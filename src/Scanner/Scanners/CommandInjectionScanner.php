<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class CommandInjectionScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'rce';
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
                if (!preg_match('/\b(exec|shell_exec|system|passthru|proc_open|popen)\s*\(/i', $line)
                    && !preg_match('/`[^`]*\$/', $line)) {
                    continue;
                }
                $tainted = preg_match('/\$_(GET|POST|REQUEST|COOKIE|SERVER)\b|\$request->(input|get|all|query)\s*\(/i', $line)
                    || preg_match('/\.\s*\$[a-zA-Z_]\w*/', $line);
                if ($tainted) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::CRITICAL,
                        'Potential command injection sink with dynamic input',
                        'Command execution function appears to use request/user-controlled input or concatenation.',
                        'Avoid shell calls for user input. Use strict allow-lists or framework APIs without shell execution.',
                    );
                } else {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::HIGH,
                        'Command execution function found',
                        'A shell execution primitive is present; validate it is not user-controlled.',
                        'Prefer safe native APIs over shell calls. If unavoidable, hardcode commands and sanitize args strictly.',
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
