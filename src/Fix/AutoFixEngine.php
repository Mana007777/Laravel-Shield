<?php

namespace Marlla3x\LaravelShield\Fix;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;

class AutoFixEngine
{
    /**
     * @param list<Issue> $issues findings from scan (used to filter by severity >= medium)
     * @return array{files: int, fixes: int, messages: list<string>}
     */
    public function apply(string $projectRoot, array $issues, bool $dryRun): array
    {
        $messages = [];
        $fixCount = 0;
        $touchedFiles = [];

        $relevant = array_values(array_filter(
            $issues,
            static fn (Issue $i) => $i->severity->atLeast(Severity::MEDIUM)
        ));

        if ($relevant === []) {
            $messages[] = 'No medium-or-higher findings to drive fixes; applying general safe patches only where applicable.';
        }

        $root = rtrim(str_replace('\\', '/', realpath($projectRoot) ?: $projectRoot), '/');

        $fixCount += $this->ensureGitignoreEnv($root, $dryRun, $touchedFiles, $messages);
        $fixCount += $this->patchEnvExampleDebug($root, $dryRun, $touchedFiles, $messages);
        $fixCount += $this->patchBladeCsrf($root, $dryRun, $touchedFiles, $messages);
        $fixCount += $this->patchWeakHashCalls($root, $dryRun, $touchedFiles, $messages);
        $fixCount += $this->patchSetcookie($root, $dryRun, $touchedFiles, $messages);

        return [
            'files' => count(array_unique($touchedFiles)),
            'fixes' => $fixCount,
            'messages' => $messages,
        ];
    }

    /**
     * @param list<string> $touchedFiles
     * @param list<string> $messages
     */
    private function backupIfNeeded(string $absPath, bool $dryRun, array &$touchedFiles, string $root): void
    {
        if ($dryRun || !is_file($absPath)) {
            return;
        }
        $backupRoot = $root.'/.shield-backup';
        $rel = str_starts_with($absPath, $root.'/') ? substr($absPath, strlen($root) + 1) : basename($absPath);
        $dest = $backupRoot.'/'.$rel;
        $dir = dirname($dest);
        if (!is_dir($dir)) {
            @mkdir($dir, 0775, true);
        }
        if (!is_file($dest)) {
            @copy($absPath, $dest);
        }
        $touchedFiles[] = $absPath;
    }

    /**
     * @param list<string> $touchedFiles
     * @param list<string> $messages
     */
    private function ensureGitignoreEnv(string $root, bool $dryRun, array &$touchedFiles, array &$messages): int
    {
        $path = $root.'/.gitignore';
        if (!is_file($path)) {
            if ($dryRun) {
                $messages[] = 'Would create .gitignore with .env entry.';
                return 1;
            }
            $this->backupIfNeeded($path, false, $touchedFiles, $root);
            @file_put_contents($path, ".env\n");
            $messages[] = 'Created .gitignore with .env.';
            $touchedFiles[] = $path;

            return 1;
        }
        $c = (string) file_get_contents($path);
        if (preg_match('/^\.env(\s|$)/m', $c) || preg_match('/^\.env\r?$/m', $c)) {
            return 0;
        }
        if ($dryRun) {
            $messages[] = 'Would append .env to .gitignore.';
            return 1;
        }
        $this->backupIfNeeded($path, false, $touchedFiles, $root);
        $append = (str_ends_with($c, "\n") ? '' : "\n").".env\n";
        file_put_contents($path, $c.$append);
        $messages[] = 'Appended .env to .gitignore.';
        $touchedFiles[] = $path;

        return 1;
    }

    /**
     * @param list<string> $touchedFiles
     * @param list<string> $messages
     */
    private function patchEnvExampleDebug(string $root, bool $dryRun, array &$touchedFiles, array &$messages): int
    {
        $path = $root.'/.env.example';
        if (!is_file($path)) {
            return 0;
        }
        $c = (string) file_get_contents($path);
        if (!preg_match('/^APP_DEBUG=true\s*$/m', $c)) {
            return 0;
        }
        if ($dryRun) {
            $messages[] = 'Would set APP_DEBUG=false in .env.example.';
            return 1;
        }
        $this->backupIfNeeded($path, false, $touchedFiles, $root);
        $new = preg_replace('/^APP_DEBUG=true\s*$/m', 'APP_DEBUG=false', $c, 1);
        file_put_contents($path, $new ?? $c);
        $messages[] = 'Set APP_DEBUG=false in .env.example.';
        $touchedFiles[] = $path;

        return 1;
    }

    /**
     * @param list<string> $touchedFiles
     * @param list<string> $messages
     */
    private function patchBladeCsrf(string $root, bool $dryRun, array &$touchedFiles, array &$messages): int
    {
        $n = 0;
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS)
        );
        /** @var \SplFileInfo $file */
        foreach ($it as $file) {
            if (!$file->isFile() || !str_ends_with($file->getFilename(), '.blade.php')) {
                continue;
            }
            $p = $file->getPathname();
            if (str_contains($p, '/vendor/') || str_contains($p, '/node_modules/')) {
                continue;
            }
            $c = (string) file_get_contents($p);
            $formRe = '/<form\b[\s\S]*?\bmethod\s*=\s*["\']?(POST|PUT|PATCH|DELETE)["\']?[\s\S]*?>/i';
            if (!preg_match($formRe, $c)) {
                continue;
            }
            $addedForms = 0;
            if (preg_match_all($formRe, $c, $fm, PREG_SET_ORDER)) {
                foreach ($fm as $m) {
                    if (!preg_match('/@csrf\b|name\s*=\s*["\']_token["\']/', $m[0])) {
                        $addedForms++;
                    }
                }
            }
            if ($addedForms === 0) {
                continue;
            }
            if ($dryRun) {
                $n += $addedForms;
                $messages[] = 'Would add @csrf to '.$addedForms.' form(s) in: '.$p;
                continue;
            }
            $this->backupIfNeeded($p, false, $touchedFiles, $root);
            $patchCount = 0;
            $new = preg_replace_callback(
                $formRe,
                static function (array $m) use (&$patchCount) {
                    $tag = $m[0];
                    if (preg_match('/@csrf\b|name\s*=\s*["\']_token["\']/', $tag)) {
                        return $tag;
                    }
                    $patchCount++;

                    return $tag."\n    @csrf";
                },
                $c
            );
            if ($new !== null && $new !== $c) {
                file_put_contents($p, $new);
                $n += $patchCount;
                $touchedFiles[] = $p;
            }
        }
        if ($n > 0 && !$dryRun) {
            $messages[] = "Added @csrf across Blade forms ({$n} insertion(s)).";
        }

        return $n;
    }

    /**
     * @param list<string> $touchedFiles
     * @param list<string> $messages
     */
    private function patchWeakHashCalls(string $root, bool $dryRun, array &$touchedFiles, array &$messages): int
    {
        $n = 0;
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS)
        );
        foreach ($it as $file) {
            if (!$file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }
            $p = $file->getPathname();
            if (str_contains($p, '/vendor/') || str_contains($p, '/node_modules/')
                || str_contains($p, '/tests/') || str_contains($p, '\\tests\\')) {
                continue;
            }
            $c = (string) file_get_contents($p);
            if (!preg_match('/\b(md5|sha1)\s*\(/', $c)) {
                continue;
            }
            if ($dryRun) {
                $messages[] = 'Would replace md5/sha1 with hash() in: '.$p;
                $n++;
                continue;
            }
            $this->backupIfNeeded($p, false, $touchedFiles, $root);
            $new = preg_replace_callback(
                '/\b(md5|sha1)\s*\(\s*([^);]+)\s*\)/',
                static function (array $m) {
                    return "hash('sha256', ".$m[2].') // shield:auto-fixed';
                },
                $c
            );
            if ($new !== null && $new !== $c) {
                file_put_contents($p, $new);
                $n++;
                $touchedFiles[] = $p;
            }
        }
        if ($n > 0 && !$dryRun) {
            $messages[] = "Replaced md5/sha1 in {$n} file(s).";
        }

        return $n;
    }

    /**
     * @param list<string> $touchedFiles
     * @param list<string> $messages
     */
    private function patchSetcookie(string $root, bool $dryRun, array &$touchedFiles, array &$messages): int
    {
        $n = 0;
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS)
        );
        foreach ($it as $file) {
            if (!$file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }
            $p = $file->getPathname();
            if (str_contains($p, '/vendor/') || str_contains($p, '/node_modules/')) {
                continue;
            }
            $c = (string) file_get_contents($p);
            if (!str_contains($c, 'setcookie(')) {
                continue;
            }
            $lines = preg_split("/\R/", $c) ?: [];
            $out = [];
            $changed = false;
            foreach ($lines as $line) {
                if (preg_match('/\/\/\s*shield:auto-fixed/', $line)
                    || !preg_match('/\bsetcookie\s*\(/', $line)) {
                    $out[] = $line;
                    continue;
                }
                if (preg_match('/,\s*true\s*,\s*true\s*\)/', $line)) {
                    $out[] = $line;
                    continue;
                }
                if (!preg_match('/^[^;]*setcookie\s*\([^)]+\)\s*;\s*$/', $line)) {
                    $out[] = $line;
                    continue;
                }
                if (substr_count($line, ',') > 1) {
                    $out[] = $line;
                    continue;
                }
                if ($dryRun) {
                    $messages[] = 'Would add secure/httponly to setcookie in: '.$p;
                    $n++;
                    $out[] = $line;
                    continue;
                }
                $newLine = preg_replace('/\)\s*;/', ', 0, \'/\', \'\', true, true); // shield:auto-fixed', $line, 1);
                if ($newLine !== null && $newLine !== $line) {
                    $out[] = $newLine;
                    $changed = true;
                    $n++;
                } else {
                    $out[] = $line;
                }
            }
            if ($changed) {
                $this->backupIfNeeded($p, false, $touchedFiles, $root);
                file_put_contents($p, implode("\n", $out));
                $touchedFiles[] = $p;
            }
        }

        return $n;
    }
}
