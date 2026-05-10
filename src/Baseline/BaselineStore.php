<?php

namespace Marlla3x\LaravelShield\Baseline;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Util\FindingHasher;
use Marlla3x\LaravelShield\Util\ShieldPaths;

class BaselineStore
{
    /**
     * @return array{hashes: list<string>, meta?: array<string, mixed>}
     */
    public static function read(string $projectRoot): array
    {
        $path = ShieldPaths::baselineFile($projectRoot);
        if (!is_file($path)) {
            return ['hashes' => []];
        }
        $raw = @file_get_contents($path);
        if ($raw === false || trim($raw) === '') {
            return ['hashes' => []];
        }
        $j = json_decode($raw, true);
        if (!is_array($j)) {
            return ['hashes' => []];
        }
        $hashes = $j['hashes'] ?? $j;
        if (!is_array($hashes)) {
            return ['hashes' => []];
        }
        $out = [];
        foreach ($hashes as $h) {
            if (is_string($h) && $h !== '') {
                $out[] = $h;
            }
        }

        return [
            'hashes' => array_values(array_unique($out)),
            'meta' => is_array($j['meta'] ?? null) ? $j['meta'] : [],
        ];
    }

    /**
     * @param list<Issue> $issues
     * @return int|false Number of unique baseline hashes written, or false on I/O failure
     */
    public static function write(string $projectRoot, array $issues, string $version): int|false
    {
        $path = ShieldPaths::baselineFile($projectRoot);
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0775, true);
        }
        $hashes = [];
        foreach ($issues as $i) {
            if (!$i instanceof Issue) {
                continue;
            }
            $hashes[] = FindingHasher::hash($i, $projectRoot);
        }
        $hashes = array_values(array_unique($hashes));
        $payload = [
            'version' => $version,
            'created_at' => gmdate('c'),
            'count' => count($hashes),
            'hashes' => $hashes,
        ];
        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        if (file_put_contents($path, $json) === false) {
            return false;
        }

        return count($hashes);
    }

    /**
     * @param list<Issue> $issues
     * @return list<Issue>
     */
    public static function filterNew(string $projectRoot, array $issues): array
    {
        $data = self::read($projectRoot);
        $known = array_fill_keys($data['hashes'], true);
        $out = [];
        foreach ($issues as $i) {
            if (!$i instanceof Issue) {
                continue;
            }
            $h = FindingHasher::hash($i, $projectRoot);
            if (!isset($known[$h])) {
                $out[] = $i;
            }
        }

        return $out;
    }
}
