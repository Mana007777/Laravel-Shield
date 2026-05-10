<?php

namespace Marlla3x\LaravelShield\Output;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\ScanResult;
use Marlla3x\LaravelShield\Risk\FileRiskBreakdown;
use Marlla3x\LaravelShield\ScanOptions;

class JsonReporter
{
    /**
     * @param list<Issue> $issues
     * @param array<string, mixed> $extra
     * @return array<string, mixed>
     */
    public function build(ScanResult $result, string $version, array $issues, ScanOptions $options, array $extra = []): array
    {
        $base = [
            'version' => $version,
            'path' => $result->scannedPath,
            'summary' => [
                'count' => count($issues),
                'by_severity' => $this->count($issues, fn (Issue $i) => $i->severity->label()),
            ],
            'issues' => array_map(fn (Issue $i) => $i->toArray(), $issues),
        ];
        if ($options->breakdown) {
            $rows = FileRiskBreakdown::aggregate($issues, $result->scannedPath);
            $top = array_slice($rows, 0, max(1, $options->top));
            $base['breakdown'] = [
                'top' => $options->top,
                'files' => array_map(static fn (array $r) => [
                    'file' => $r['file'],
                    'risk_score' => $r['score'],
                    'findings' => $r['count'],
                ], $top),
            ];
        }
        if ($extra !== []) {
            $base = array_merge($base, $extra);
        }

        return $base;
    }

    /**
     * @param list<Issue> $issues
     */
    public function toJson(ScanResult $result, string $version, array $issues, ScanOptions $options, array $extra = []): string
    {
        return (string) json_encode($this->build($result, $version, $issues, $options, $extra), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
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
