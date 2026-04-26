<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class CryptoScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'crypto';
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
                if (preg_match('/\b(md5|sha1)\s*\(/i', $line)) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::HIGH,
                        'Weak hash algorithm used for security-sensitive context',
                        'Detected `md5()`/`sha1()` call; these are unsuitable for password/integrity security contexts.',
                        'Use `password_hash()` for passwords or `hash_hmac("sha256", ...)` for integrity with secret keys.',
                    );
                }
                if (preg_match('/openssl_encrypt\s*\(/i', $line) && preg_match('/(DES|RC2|RC4|ECB|3DES)/i', $line)) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::HIGH,
                        'Weak/legacy cipher mode detected',
                        'Cipher/mode appears to include insecure algorithms or ECB mode.',
                        'Use authenticated encryption modes (e.g. AES-256-GCM / libsodium) with unique nonces.',
                    );
                }
                if (preg_match('/\b(rand|mt_rand)\s*\(/i', $line) && preg_match('/token|secret|otp|code|nonce|key/i', $line)) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::MEDIUM,
                        'Non-cryptographic RNG used in security context',
                        'Detected `rand()/mt_rand()` near token/secret generation.',
                        'Use `random_bytes()` or `random_int()` for security-sensitive randomness.',
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
