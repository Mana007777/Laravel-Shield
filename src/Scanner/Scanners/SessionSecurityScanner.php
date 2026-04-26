<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class SessionSecurityScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'session';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        $cfg = $context->basePath.'/config/session.php';
        if (is_file($cfg)) {
            $c = (string) file_get_contents($cfg);
            if (preg_match("/'secure'\\s*=>\\s*false/i", $c)) {
                $issues[] = $this->makeIssue(
                    $cfg,
                    $this->lineOf($c, "'secure'"),
                    Severity::HIGH,
                    'Session cookie `secure` is disabled',
                    'Session cookies may be transmitted over HTTP.',
                    'Set `secure` to `true` (or `env(SESSION_SECURE_COOKIE, true)` in production).',
                );
            }
            if (preg_match("/'http_only'\\s*=>\\s*false/i", $c)) {
                $issues[] = $this->makeIssue(
                    $cfg,
                    $this->lineOf($c, "'http_only'"),
                    Severity::HIGH,
                    'Session cookie `http_only` is disabled',
                    'Client-side scripts may access session cookies.',
                    'Enable `http_only` to reduce cookie theft via XSS.',
                );
            }
            if (preg_match("/'same_site'\\s*=>\\s*null/i", $c) || preg_match("/'same_site'\\s*=>\\s*['\"]none['\"]/i", $c)) {
                $issues[] = $this->makeIssue(
                    $cfg,
                    $this->lineOf($c, "'same_site'"),
                    Severity::MEDIUM,
                    'Weak or disabled SameSite policy',
                    'Session cookie SameSite appears unset or permissive.',
                    'Prefer `lax` or `strict` unless cross-site requirements explicitly need `none` with HTTPS.',
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
                if (preg_match('/cookie\s*\(.*(false\s*,\s*false|false\s*\))/i', $line)) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::MEDIUM,
                        'Manual cookie creation may disable secure/httpOnly flags',
                        'Detected cookie call with boolean flags that may weaken cookie security.',
                        'Set cookie `secure`, `httpOnly`, and `sameSite` explicitly for auth/session cookies.',
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

