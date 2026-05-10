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

        try {
            return $this->filterSuppressed($this->getKey(), $this->dedupe($this->scanUnsafe($context)));
        } catch (\Throwable $e) {
            return [
                $this->makeIssue(
                    $context->basePath.'/composer.json',
                    1,
                    Severity::MEDIUM,
                    'Secrets scanner encountered an error',
                    $e->getMessage(),
                    'Re-run with verbose PHP errors or report a bug if this persists.',
                    'Scanner failure may hide secret exposure findings.',
                    'secrets-scanner-error',
                ),
            ];
        }
    }

    private function scanUnsafe(ScanContext $context): array
    {
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
                        null,
                        'hardcoded-pattern',
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
                        null,
                        'hardcoded-credential-literal',
                    );
                }
                if ($context->shouldScanEntropyForFile($file)) {
                    $issues = array_merge($issues, $this->entropyLine($file, $n, $line, $context));
                }
            }
        }

        return $issues;
    }

    /**
     * @return list<Issue>
     */
    private function entropyLine(string $file, int $lineNo, string $line, ScanContext $context): array
    {
        $issues = [];
        $threshold = $context->entropyThreshold;
        $varHint = '';
        if (preg_match('/\$(\w*?(?:key|secret|token|password|pass|pwd|auth|credential|api)\w*)\b/i', $line, $vm)) {
            $varHint = $vm[1];
        }
        $sensitiveVar = $varHint !== '';
        if (preg_match_all('/[\'"]([^\'"]{17,})[\'"]/', $line, $m)) {
            foreach ($m[1] as $literal) {
                if (preg_match('/^\d+$/', $literal)) {
                    continue;
                }
                $e = self::shannonEntropy($literal);
                if ($e <= $threshold) {
                    continue;
                }
                $near = $sensitiveVar || (bool) preg_match(
                    '/\b(key|secret|token|password|pass|pwd|auth|credential|api)\s*[=:>]/i',
                    $line
                );
                $sev = $near ? Severity::HIGH : Severity::MEDIUM;
                $nearMsg = $near
                    ? ($varHint !== ''
                        ? sprintf('High-entropy string (entropy: %.2f) near variable $%s', $e, $varHint)
                        : sprintf('High-entropy string (entropy: %.2f) near sensitive identifier', $e))
                    : sprintf('High-entropy string (entropy: %.2f) in source', $e);
                $issues[] = $this->makeIssue(
                    $file,
                    $lineNo,
                    $sev,
                    $nearMsg,
                    'Long random-looking literals may be secrets; verify they are not hardcoded credentials.',
                    'Move to environment or secret manager; rotate if exposed.',
                    null,
                    'high-entropy-string',
                );
                break;
            }
        }

        return $issues;
    }

    private static function shannonEntropy(string $s): float
    {
        $len = strlen($s);
        if ($len === 0) {
            return 0.0;
        }
        $freq = count_chars($s, 1);
        $h = 0.0;
        foreach ($freq as $c => $cnt) {
            $p = $cnt / $len;
            $h -= $p * log($p, 2);
        }

        return round($h, 4);
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
