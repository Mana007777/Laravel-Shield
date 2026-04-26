<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class PublicExposureScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'exposure';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        $public = $context->basePath.'/public';
        if (!is_dir($public)) {
            return [];
        }

        $criticalPaths = [
            $public.'/.env',
            $public.'/.git/HEAD',
            $public.'/.git/config',
        ];
        foreach ($criticalPaths as $p) {
            if (is_file($p)) {
                $issues[] = $this->makeIssue(
                    $p,
                    1,
                    Severity::CRITICAL,
                    'Sensitive file appears inside public web root',
                    'A sensitive file in `public/` may be web-accessible.',
                    'Remove immediately, rotate secrets/keys, and verify web server denies dotfile access.',
                );
            }
        }

        $highPatterns = [
            '*.sql',
            '*.bak',
            '*.old',
            '*.zip',
            '*.tar',
            '*.gz',
            'phpinfo.php',
            'info.php',
            'test.php',
        ];
        foreach ($highPatterns as $pat) {
            foreach (glob($public.'/'.$pat) ?: [] as $f) {
                if (!is_file($f)) {
                    continue;
                }
                $issues[] = $this->makeIssue(
                    $f,
                    1,
                    Severity::HIGH,
                    'Potentially exposed backup/debug artifact in public directory',
                    'Backup, debug, or archive file exists under `public/`.',
                    'Delete from web root and move backups outside deploy artifacts.',
                );
            }
        }

        foreach (glob($public.'/storage/**/*.php') ?: [] as $f) {
            if (!is_file($f)) {
                continue;
            }
            $issues[] = $this->makeIssue(
                $f,
                1,
                Severity::HIGH,
                'Executable PHP file found under public storage path',
                'User-controlled upload paths should not contain executable PHP files.',
                'Block PHP execution in upload directories via web server config and clean suspicious files.',
            );
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

