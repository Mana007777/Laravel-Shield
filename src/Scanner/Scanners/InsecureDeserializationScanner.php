<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class InsecureDeserializationScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'deserialize';
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
                if (!preg_match('/\bunserialize\s*\(/i', $line)) {
                    continue;
                }
                $tainted = preg_match('/\$_(GET|POST|REQUEST|COOKIE)\b|\$request->(input|get|all|query)\s*\(/i', $line);
                $issues[] = $this->makeIssue(
                    $file,
                    $n,
                    $tainted ? Severity::CRITICAL : Severity::HIGH,
                    'Potential insecure deserialization',
                    'Use of `unserialize()` can trigger object injection, especially with user-controlled input.',
                    'Prefer `json_decode()` for untrusted data, or `unserialize($x, [\'allowed_classes\' => false])` with strict controls.',
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
