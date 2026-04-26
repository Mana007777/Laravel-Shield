<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class HardcodedSecretsScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'secrets';
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
                if (preg_match('/(AIza[0-9A-Za-z_\-]{35}|sk_live_[0-9a-zA-Z]{16,}|xox[baprs]-[0-9A-Za-z\-]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----)/', $line)) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::CRITICAL,
                        'Possible hardcoded secret or private key material',
                        'Detected token/key-like pattern directly in source code.',
                        'Move secrets to environment/secret manager and rotate any leaked credentials immediately.',
                    );
                    continue;
                }
                if (preg_match('/\b(password|passwd|secret|token|api[_-]?key)\b\s*[:=]\s*[\'"][^\'"]{8,}[\'"]/i', $line)
                    && !preg_match('/env\s*\(/i', $line)) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::HIGH,
                        'Potential hardcoded credential assignment',
                        'Source line appears to assign a secret/token literal in code.',
                        'Use env variables or a vault and avoid committing credentials in source.',
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
