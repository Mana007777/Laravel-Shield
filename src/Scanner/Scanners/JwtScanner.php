<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class JwtScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'jwt';
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
                if (preg_match('/\b(HS256|RS256|EdDSA|JWT::decode|firebase\\\\jwt|tymon\\\\jwt)/i', $line) === 0) {
                    continue;
                }
                if (preg_match('/\bnone\b/i', $line) || preg_match('/verify\s*=>\s*false/i', $line)) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::CRITICAL,
                        'JWT verification appears disabled or algorithm is `none`',
                        'Token verification flags/algorithm look insecure.',
                        'Enforce strict allowed algorithms and signature verification; reject `none`.',
                    );
                    continue;
                }
                if (preg_match('/decode\s*\(.*\$_(GET|POST|REQUEST)|decode\s*\(.*\$request->(input|get|query)\(/i', $line)
                    && !preg_match('/(exp|nbf|aud|iss|sub|leeway)/i', $line)) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::HIGH,
                        'JWT decode with user input and weak claim validation visibility',
                        'Decoded JWT from request input without obvious checks for expiry/audience/issuer on this line.',
                        'Validate signature and critical claims: exp, nbf, iss, aud, and key ID handling.',
                    );
                } else {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::INFO,
                        'JWT handling detected',
                        'JWT encode/decode call found; review claim validation and key rotation strategy.',
                        'Ensure strict algorithm allow-list, short expirations, refresh strategy, and key rotation.',
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
