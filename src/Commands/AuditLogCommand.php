<?php

namespace Marlla3x\LaravelShield\Commands;

use Illuminate\Console\Command;
use Marlla3x\LaravelShield\Util\ShieldPaths;

class AuditLogCommand extends Command
{
    protected $signature = 'shield:audit-log
        {path? : Project root}
        {--since= : Filter: 1d, 7d, 30d, 90d}';

    protected $description = 'Show recent Laravel Shield scan audit history';

    public function handle(): int
    {
        $root = rtrim((string) ($this->argument('path') ?: base_path()), '/\\');
        $path = ShieldPaths::auditLogFile($root);
        if (!is_file($path)) {
            $this->warn('No audit log yet.');

            return 0;
        }
        $since = (string) ($this->option('since') ?: '');
        $cutoff = $this->cutoffUtc($since);
        $lines = file($path, FILE_IGNORE_NEW_LINES) ?: [];
        $rows = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $j = json_decode($line, true);
            if (!is_array($j) || !isset($j['ts'])) {
                continue;
            }
            $ts = strtotime((string) $j['ts']);
            if ($cutoff !== null && $ts !== false && $ts < $cutoff) {
                continue;
            }
            $rows[] = $j;
        }
        $rows = array_slice(array_reverse($rows), 0, 20);
        $this->line('Time (UTC)          Git     Score  Trend  Findings  Fix');
        $this->line(str_repeat('-', 72));
        foreach ($rows as $idx => $r) {
            $score = (int) ($r['score'] ?? 0);
            $trend = '→';
            $older = $rows[$idx + 1] ?? null;
            if ($older !== null) {
                $prev = (int) ($older['score'] ?? 0);
                $trend = $score > $prev ? '↑' : ($score < $prev ? '↓' : '→');
            }
            $git = (string) ($r['git'] ?? '-');
            $git = strlen($git) > 7 ? substr($git, 0, 7) : $git;
            $this->line(sprintf(
                '%-19s %-7s %3d/100  %s     %-8d %s',
                substr((string) $r['ts'], 0, 19),
                $git,
                $score,
                $trend,
                (int) ($r['findings_total'] ?? 0),
                !empty($r['fix_applied']) ? (string) ($r['fix_count'] ?? 0) : '-'
            ));
        }

        return 0;
    }

    private function cutoffUtc(string $since): ?int
    {
        if ($since === '') {
            return null;
        }
        $map = ['1d' => 1, '7d' => 7, '30d' => 30, '90d' => 90];
        if (!isset($map[$since])) {
            return null;
        }
        $days = $map[$since];

        return time() - $days * 86400;
    }
}
