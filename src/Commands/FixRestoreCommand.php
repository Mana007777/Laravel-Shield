<?php

namespace Marlla3x\LaravelShield\Commands;

use Illuminate\Console\Command;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

class FixRestoreCommand extends Command
{
    protected $signature = 'shield:fix-restore
        {path? : Project root (default: base_path)}';

    protected $description = 'Restore files from .shield-backup/ after shield:scan --fix';

    public function handle(): int
    {
        $root = rtrim((string) ($this->argument('path') ?: base_path()), '/\\');
        $backup = $root.'/.shield-backup';
        if (!is_dir($backup)) {
            $this->warn('No .shield-backup directory found.');

            return 0;
        }
        $n = 0;
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($backup, \FilesystemIterator::SKIP_DOTS)
        );
        /** @var SplFileInfo $file */
        foreach ($it as $file) {
            if (!$file->isFile()) {
                continue;
            }
            $rel = substr($file->getPathname(), strlen($backup) + 1);
            $dest = $root.DIRECTORY_SEPARATOR.str_replace('/', DIRECTORY_SEPARATOR, $rel);
            $dir = dirname($dest);
            if (!is_dir($dir)) {
                @mkdir($dir, 0775, true);
            }
            if (@copy($file->getPathname(), $dest)) {
                $n++;
            }
        }
        $this->info("Restored {$n} file(s) from .shield-backup/.");

        return 0;
    }
}
