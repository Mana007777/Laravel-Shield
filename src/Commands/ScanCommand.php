<?php

namespace Marlla3x\LaravelShield\Commands;

use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanCommandRunner;
use Marlla3x\LaravelShield\ScanOptions;
use Illuminate\Console\Command;

class ScanCommand extends Command
{
    protected $signature = 'shield:scan
        {path? : Root path to scan (default: config shield.path or app root)}
        {--format=table : Output: table, json, summary, or github}
        {--severity= : Minimum severity to report (critical, high, medium, low, info)}
        {--only= : Comma-separated scanner keys to run}
        {--exclude= : Extra path segments to exclude (comma list)}
        {--fix-hints : Print recommendation per issue in table}
        {--ci : Exit 1 if issues are found}
        {--output= : Also write a JSON file}
        {--watch : Polling re-scan (Ctrl+C to stop)}
        {--no-score : Hide 0–100 security score}
        {--diff : Only report findings not in the baseline}
        {--breakdown : Group risk by file/controller}
        {--top=10 : With --breakdown, limit to N riskiest files}
        {--fix : Apply safe automatic patches}
        {--dry-run : With --fix, show changes without writing}
        {--no-entropy : Skip entropy-based secret heuristics}
        {--entropy-threshold=4.5 : Entropy threshold (bits per character)}
        {--all-projects : Scan all paths from config shield.projects}
        {--i|interactive : Interactive finding browser after scan}
        {--update-hints : Run composer outdated hints (dependency scanner)}';

    protected $description = 'Run Laravel Shield security scan';

    public function handle(ScanCommandRunner $runner): int
    {
        $p = (string) ($this->argument('path') ?: config('shield.path', base_path()));
        $sev = $this->option('severity');
        $min = is_string($sev) && $sev !== '' ? Severity::fromString($sev) : null;
        $only = (string) ($this->option('only') ?? '');
        $ex = (string) ($this->option('exclude') ?? '');
        $excludes = $ex === '' ? (array) config('shield.exclude', []) : array_merge(
            (array) config('shield.exclude', []),
            array_map('trim', explode(',', $ex))
        );
        $projects = [];
        $cfgProj = config('shield.projects', []);
        if (is_array($cfgProj)) {
            foreach ($cfgProj as $label => $path) {
                if (is_string($label) && is_string($path) && $path !== '') {
                    $projects[$label] = $path;
                }
            }
        }
        $entropy = (float) ($this->option('entropy-threshold') ?? config('shield.entropy_threshold', 4.5));
        $opt = new ScanOptions(
            path: $p,
            format: (string) $this->option('format'),
            minSeverity: $min,
            only: $only === '' ? [] : array_map('trim', explode(',', $only)),
            exclude: $excludes,
            fixHints: (bool) $this->option('fix-hints'),
            ci: (bool) $this->option('ci'),
            output: $this->option('output'),
            watch: (bool) $this->option('watch'),
            showScore: !(bool) $this->option('no-score'),
            diff: (bool) $this->option('diff'),
            breakdown: (bool) $this->option('breakdown'),
            top: max(1, (int) $this->option('top')),
            fix: (bool) $this->option('fix'),
            fixDryRun: (bool) $this->option('dry-run'),
            noEntropy: (bool) $this->option('no-entropy'),
            entropyThreshold: $entropy,
            allProjects: (bool) $this->option('all-projects'),
            interactive: (bool) $this->option('interactive'),
            updateHints: (bool) $this->option('update-hints'),
            projectLabel: null,
            projectPaths: $projects,
        );
        if ($opt->watch) {
            return $runner->runWatch($opt, $this->getOutput(), (float) config('shield.watch_interval', 2.0));
        }
        return $runner->run($opt, $this->getOutput());
    }
}
