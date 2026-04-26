<?php

namespace Marlla3x\LaravelShield\Commands;

use Illuminate\Console\Command;

class AddIgnoreCommand extends Command
{
    protected $signature = 'shield:ignore
        {file : File path to patch (relative to cwd or absolute)}
        {line : 1-based line number the comment is inserted before}
        {scanner=all : Scanner id (env, sql, …) or "all"}';

    protected $description = 'Insert a // shield:ignore line before a line (stops the scanner for that line)';

    public function handle(): int
    {
        $file = (string) $this->argument('file');
        if (!is_file($file) && is_file(getcwd().'/'.$file)) {
            $file = getcwd().'/'.$file;
        }
        if (!is_file($file)) {
            $this->error('File not found: '.$this->argument('file'));
            return self::FAILURE;
        }
        $line = max(1, (int) $this->argument('line'));
        $scanner = (string) $this->argument('scanner');
        $c = (string) file_get_contents($file);
        $lines = preg_split("/\R/", $c) ?: [];
        $i = $line - 1;
        if ($i < 0 || $i >= count($lines)) {
            $this->error('Line is out of range for this file');
            return self::FAILURE;
        }
        if (str_contains($lines[$i] ?? '', 'shield:ignore')) {
            $this->warn('That line (or a nearby one) may already be suppressed');
        }
        $tag = '// shield:ignore: '.trim($scanner);
        array_splice($lines, $i, 0, [$tag]);
        if (file_put_contents($file, implode("\n", $lines).(str_ends_with($c, "\n") ? "\n" : '')) === false) {
            $this->error('Could not write file');
            return self::FAILURE;
        }
        $this->info('Added suppression: '.$tag);
        return self::SUCCESS;
    }
}
