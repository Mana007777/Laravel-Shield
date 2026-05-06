<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
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

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($public, FilesystemIterator::SKIP_DOTS)
        );
        /** @var \SplFileInfo $file */
        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }
            $f = $file->getPathname();
            $relative = ltrim(str_replace($public, '', $f), '/\\');
            $name = strtolower($file->getFilename());
            $ext = strtolower($file->getExtension());

            if ($name === 'phpinfo.php' || $name === 'info.php' || $name === 'test.php') {
                $issues[] = $this->makeIssue(
                    $f,
                    1,
                    Severity::HIGH,
                    'Debug probe file exposed in public directory',
                    'A diagnostic/debug PHP file is reachable from the public web root.',
                    'Delete probe files from production images and block execution of unmanaged scripts.',
                );
            }

            if (in_array($ext, ['sql', 'bak', 'old', 'zip', 'tar', 'gz', '7z', 'rar', 'log'], true)) {
                $issues[] = $this->makeIssue(
                    $f,
                    1,
                    Severity::HIGH,
                    'Potentially exposed backup or artifact in public directory',
                    'Backup/archive/log artifact exists under `public/` and may disclose source/data.',
                    'Move artifacts out of web root, enforce deploy allowlists, and deny direct download where possible.',
                );
            }

            if (str_starts_with(str_replace('\\', '/', $relative), 'storage/') && $ext === 'php') {
                $issues[] = $this->makeIssue(
                    $f,
                    1,
                    Severity::CRITICAL,
                    'Executable PHP file found under public storage path',
                    'User-controlled upload paths should not contain executable PHP files.',
                    'Block PHP execution in upload directories at web-server level and quarantine suspicious files immediately.',
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

