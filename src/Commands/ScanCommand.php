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
        {--format=table : Output: table, json, or summary}
        {--severity= : Minimum severity to report (critical, high, medium, low, info)}
        {--only= : Comma-separated scanner keys to run}
        {--exclude= : Extra path segments to exclude (comma list)}
        {--fix-hints : Print recommendation per issue in table}
        {--ci : Exit 1 if issues are found}
        {--output= : Also write a JSON file}
        {--watch : Polling re-scan (Ctrl+C to stop)}
        {--no-score : Hide 0–100 security score}';

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
        );
        if ($opt->watch) {
            return $runner->runWatch($opt, $this->getOutput(), 2.0);
        }
        return $runner->run($opt, $this->getOutput());
    }
}
