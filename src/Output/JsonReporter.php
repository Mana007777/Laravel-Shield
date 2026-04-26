<?php

namespace Marlla3x\LaravelShield\Output;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\ScanResult;

class JsonReporter
{
    /**
     * @param list<Issue> $issues
     * @return array<string, mixed>
     */
    public function build(ScanResult $result, string $version, array $issues): array
    {
        return [
            'version' => $version,
            'path' => $result->scannedPath,
            'summary' => [
                'count' => count($issues),
                'by_severity' => $this->count($issues, fn (Issue $i) => $i->severity->label()),
            ],
            'issues' => array_map(fn (Issue $i) => $i->toArray(), $issues),
        ];
    }

    public function toJson(ScanResult $result, string $version, array $issues): string
    {
        return (string) json_encode($this->build($result, $version, $issues), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    /**
     * @param list<Issue> $issues
     * @param callable(Issue): string $f
     * @return array<string, int>
     */
    private function count(array $issues, callable $f): array
    {
        $m = [];
        foreach ($issues as $i) {
            $k = $f($i);
            $m[$k] = ($m[$k] ?? 0) + 1;
        }
        ksort($m);
        return $m;
    }
}
