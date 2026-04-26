<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class CorsScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'cors';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        $cfg = $context->basePath.'/config/cors.php';
        if (is_file($cfg)) {
            $c = (string) file_get_contents($cfg);
            if (preg_match('/allowed_origins\s*[\'"]?\s*=>\s*\[[^\]]*[\'"]\*[\'"]/s', $c)) {
                $issues[] = $this->makeIssue(
                    $cfg,
                    $this->lineOf($c, 'allowed_origins'),
                    Severity::HIGH,
                    'CORS allows any origin (`*`)',
                    'Cross-origin policy appears to trust all origins.',
                    'Use explicit frontend origins in production and restrict methods/headers as tightly as possible.',
                );
            }
            if (preg_match('/supports_credentials\s*[\'"]?\s*=>\s*true/i', $c) && str_contains($c, "'*'")) {
                $issues[] = $this->makeIssue(
                    $cfg,
                    $this->lineOf($c, 'supports_credentials'),
                    Severity::CRITICAL,
                    'Credentials with permissive CORS policy',
                    'CORS credentials enabled with wildcard-style origin config is dangerous.',
                    'Disable credentials or use exact allowed origins; never combine credentials with broad origin patterns.',
                );
            }
        }

        foreach ($context->allPhpFiles() as $file) {
            $lines = $this->readLines($file);
            foreach ($lines as $i => $line) {
                $n = $i + 1;
                if (preg_match('/^\s*(\/\/|#|\/\*|\*)/', ltrim($line))) {
                    continue;
                }
                if (preg_match('/Access-Control-Allow-Origin/i', $line) && str_contains($line, '*')) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::HIGH,
                        'Manual CORS header allows any origin',
                        'Source sets `Access-Control-Allow-Origin: *` manually.',
                        'Prefer centralized CORS middleware config and explicit allowed origins.',
                    );
                }
            }
        }

        return $this->filterSuppressed($this->getKey(), $this->dedupe($issues));
    }

    private function lineOf(string $content, string $needle): int
    {
        $p = stripos($content, $needle);
        if ($p === false) {
            return 1;
        }
        return 1 + substr_count(substr($content, 0, $p), "\n");
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
