<?php

namespace Marlla3x\LaravelShield;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RegexIterator;
use FilesystemIterator;

class ScanContext
{
    /**
     * @var list<string>|null
     */
    private ?array $ignorePatterns = null;

    /**
     * @param list<string> $exclude
     * @param list<string> $onlyScanners
     */
    public function __construct(
        public string $basePath,
        public array $exclude = ['vendor', 'node_modules', 'storage', 'bootstrap/cache', 'tests', 'fixtures'],
        public array $onlyScanners = [],
    ) {
        $this->basePath = rtrim(realpath($basePath) ?: $basePath, '/');
    }

    public function shouldRun(string $scannerKey): bool
    {
        if ($this->onlyScanners === []) {
            return true;
        }
        $aliases = [
            'mass-assignment' => 'mass',
            'assign' => 'mass',
            'deps' => 'dependency',
            'dependencies' => 'dependency',
            'packages' => 'dependency',
            'mw' => 'middleware',
            'http' => 'middleware',
            'cmd' => 'rce',
            'command' => 'rce',
            'exec' => 'rce',
            'deser' => 'deserialize',
            'uploads' => 'upload',
            'keys' => 'secrets',
            'cross-origin' => 'cors',
            'traversal' => 'redirect',
            'lfi' => 'redirect',
            'cryptography' => 'crypto',
            'tokens' => 'jwt',
            'rest' => 'api',
            'endpoint' => 'api',
            'endpoints' => 'api',
            'cookies' => 'session',
            'http-headers' => 'headers',
            'security-headers' => 'headers',
            'idor-bola' => 'idor',
            'bola' => 'idor',
            'public-files' => 'exposure',
            'leaks' => 'exposure',
        ];
        $toCanon = function (string $k) use ($aliases): string {
            $k = strtolower($k);
            return $aliases[$k] ?? $k;
        };
        $want = $toCanon($scannerKey);
        foreach ($this->onlyScanners as $o) {
            if ($toCanon($o) === $want || $toCanon($o) === $toCanon($scannerKey)) {
                return true;
            }
        }
        return false;
    }

    protected function isExcludedPath(string $absolutePath): bool
    {
        $rel = ltrim(str_replace($this->basePath, '', $absolutePath), '/\\');
        $rel = str_replace('\\', '/', $rel);
        foreach ($this->exclude as $e) {
            $e = trim($e, '/\\');
            if ($e === '') {
                continue;
            }
            $e = str_replace('\\', '/', $e);
            if (str_starts_with($rel, $e.'/') || $rel === $e) {
                return true;
            }
        }
        if ($this->matchesIgnorePattern($rel)) {
            return true;
        }
        return false;
    }

    /**
     * @return list<string> absolute paths
     */
    public function findFiles(string $subDir, string $extension = 'php', bool $requireExists = true): array
    {
        $dir = $this->basePath.($subDir !== '' ? '/'.$subDir : '');
        if ($requireExists && !is_dir($dir)) {
            return [];
        }
        if (!$requireExists && !is_dir($dir)) {
            return [];
        }

        $out = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
        );
        /** @var \SplFileInfo $file */
        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }
            $path = $file->getPathname();
            if ($this->isExcludedPath($path)) {
                continue;
            }
            if (strtolower($file->getExtension()) !== strtolower($extension)) {
                continue;
            }
            $out[] = $path;
        }
        return $out;
    }

    /**
     * @return list<string> absolute paths in project matching glob relative to base
     */
    public function globProject(string $pattern): array
    {
        $path = $this->basePath.'/'.$pattern;
        if (!is_dir($this->basePath)) {
            return [];
        }
        $files = glob($path) ?: [];
        $out = [];
        foreach ($files as $f) {
            if (is_file($f) && !$this->isExcludedPath($f)) {
                $out[] = $f;
            }
        }
        return $out;
    }

    /**
     * @return list<string> all php files under base, respecting excludes
     */
    public function allPhpFiles(): array
    {
        return $this->findFiles('', 'php', true);
    }

    /**
     * @return list<string> blade files
     */
    public function allBladeFiles(): array
    {
        $dir = $this->basePath;
        if (!is_dir($dir)) {
            return [];
        }
        $out = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
        );
        /** @var \SplFileInfo $file */
        foreach ($iterator as $file) {
            if (!$file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }
            if (!str_ends_with($file->getFilename(), '.blade.php')) {
                continue;
            }
            $path = $file->getPathname();
            if ($this->isExcludedPath($path)) {
                continue;
            }
            $out[] = $path;
        }
        return $out;
    }

    private function matchesIgnorePattern(string $relativePath): bool
    {
        foreach ($this->getIgnorePatterns() as $pattern) {
            if ($this->pathMatchesPattern($relativePath, $pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return list<string>
     */
    private function getIgnorePatterns(): array
    {
        if ($this->ignorePatterns !== null) {
            return $this->ignorePatterns;
        }

        $paths = [
            $this->basePath.'/.gitignore',
            $this->basePath.'/.shieldignore',
        ];

        $patterns = ['.git/'];
        foreach ($paths as $path) {
            if (!is_file($path)) {
                continue;
            }
            $content = (string) @file_get_contents($path);
            if ($content === '') {
                continue;
            }
            $lines = preg_split("/\R/", $content) ?: [];
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '' || str_starts_with($line, '#') || str_starts_with($line, '!')) {
                    continue;
                }
                $patterns[] = str_replace('\\', '/', $line);
            }
        }

        $this->ignorePatterns = array_values(array_unique($patterns));
        return $this->ignorePatterns;
    }

    private function pathMatchesPattern(string $relativePath, string $pattern): bool
    {
        $path = ltrim(str_replace('\\', '/', $relativePath), '/');
        $p = ltrim(str_replace('\\', '/', trim($pattern)), '/');
        if ($p === '') {
            return false;
        }

        if (str_ends_with($p, '/')) {
            $dir = rtrim($p, '/');
            return $path === $dir || str_starts_with($path, $dir.'/');
        }

        if (str_contains($p, '*') || str_contains($p, '?')) {
            return fnmatch($p, $path) || fnmatch($p, basename($path));
        }

        return $path === $p || str_starts_with($path, $p.'/');
    }
}
