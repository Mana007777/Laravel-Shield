<?php

namespace Marlla3x\LaravelShield\Audit;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanOptions;
use Marlla3x\LaravelShield\SecurityScore;
use Marlla3x\LaravelShield\Util\ShieldPaths;

class ScanAuditLogger
{
    /**
     * @param list<Issue> $issues
     */
    public function append(
        string $projectRoot,
        ScanOptions $options,
        array $issues,
        int $fixCount,
        bool $fixRan,
    ): void {
        $path = ShieldPaths::auditLogFile($projectRoot);
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0775, true);
        }
        $bySev = [];
        foreach (Severity::cases() as $c) {
            $bySev[$c->label()] = 0;
        }
        foreach ($issues as $i) {
            if (!$i instanceof Issue) {
                continue;
            }
            $bySev[$i->severity->label()] = ($bySev[$i->severity->label()] ?? 0) + 1;
        }
        $record = [
            'ts' => gmdate('c'),
            'git' => $this->gitHead($projectRoot),
            'by_severity' => $bySev,
            'score' => SecurityScore::compute($issues),
            'flags' => [
                'format' => $options->format,
                'severity' => $options->minSeverity?->label(),
                'ci' => $options->ci,
                'diff' => $options->diff,
                'breakdown' => $options->breakdown,
                'fix' => $options->fix,
                'fix_dry_run' => $options->fixDryRun,
                'all_projects' => $options->allProjects,
            ],
            'fix_applied' => $fixRan,
            'fix_count' => $fixCount,
            'findings_total' => count($issues),
        ];
        @file_put_contents($path, json_encode($record, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n", FILE_APPEND);
    }

    private function gitHead(string $root): ?string
    {
        $p = new \Symfony\Component\Process\Process(['git', 'rev-parse', '--short', 'HEAD'], $root);
        $p->run();
        if (!$p->isSuccessful()) {
            return null;
        }
        $o = trim($p->getOutput());

        return $o !== '' ? $o : null;
    }
}
