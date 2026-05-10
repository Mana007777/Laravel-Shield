<?php

namespace Marlla3x\LaravelShield\Commands;

use Marlla3x\LaravelShield\Baseline\BaselineStore;
use Marlla3x\LaravelShield\ScanOptions;
use Marlla3x\LaravelShield\Scanner\ScanManager;
use Marlla3x\LaravelShield\Version;
use Illuminate\Console\Command;

class BaselineCommand extends Command
{
    protected $signature = 'shield:baseline
        {path? : Root path (default: config shield.path)}';

    protected $description = 'Save current scan findings as a baseline for shield:scan --diff';

    public function handle(): int
    {
        $p = (string) ($this->argument('path') ?: config('shield.path', base_path()));
        $ex = (array) config('shield.exclude', []);
        $opt = new ScanOptions(path: $p, exclude: $ex, format: 'summary');
        try {
            $result = (new ScanManager())->run($opt);
            $n = BaselineStore::write($p, $result->issues, Version::VERSION);
            if ($n === false) {
                $this->error('Could not write baseline file.');

                return 1;
            }
            $this->info('Baseline saved: '.$n.' findings recorded.');

            return 0;
        } catch (\Throwable $e) {
            $this->warn('shield: baseline failed: '.$e->getMessage());

            return 1;
        }
    }
}
