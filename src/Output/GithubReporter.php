<?php

namespace Marlla3x\LaravelShield\Output;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\ScanResult;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\SecurityScore;
use Symfony\Component\Console\Output\OutputInterface;

class GithubReporter
{
    /**
     * @param list<Issue> $issues
     */
    public function writeAnnotations(OutputInterface $out, array $issues): void
    {
        foreach ($issues as $i) {
            $out->writeln($this->annotationLine($i));
        }
    }

    public function annotationLine(Issue $i): string
    {
        $level = match ($i->severity) {
            Severity::CRITICAL, Severity::HIGH => 'error',
            Severity::MEDIUM, Severity::LOW => 'warning',
            Severity::INFO => 'notice',
        };
        $file = str_replace('\\', '/', $i->file);
        $col = 1;
        $rule = $i->rule !== '' ? $i->rule : 'finding';
        $msg = 'shield['.$rule.'] '.str_replace(["\r", "\n"], ' ', $i->title);
        if ($i->projectLabel !== null && $i->projectLabel !== '') {
            $msg = '['.$i->projectLabel.'] '.$msg;
        }

        return sprintf('::%s file=%s,line=%d,col=%d::%s', $level, $file, max(1, $i->line), $col, $msg);
    }

    /**
     * @param list<Issue> $issues
     */
    public function appendStepSummary(string $path, ScanResult $result, array $issues, string $version): void
    {
        $score = SecurityScore::compute($issues);
        $byFile = [];
        foreach ($issues as $i) {
            $f = str_replace('\\', '/', $i->file);
            $byFile[$f] ??= [];
            $byFile[$f][] = $i;
        }
        ksort($byFile);
        $lines = [];
        $lines[] = '## Laravel Shield';
        $lines[] = '';
        $lines[] = 'Version: `'.$version.'` · Path: `'.$result->scannedPath.'` · Score: **'.$score.'/100** · Findings: **'.count($issues).'**';
        $lines[] = '';
        $lines[] = '| File | Severity | Rule | Title |';
        $lines[] = '| --- | --- | --- | --- |';
        foreach ($byFile as $file => $list) {
            foreach ($list as $i) {
                $lines[] = sprintf(
                    '| `%s` | %s | `%s` | %s |',
                    $file,
                    $i->severity->label(),
                    $i->rule,
                    str_replace('|', '\\|', $i->title)
                );
            }
        }
        $lines[] = '';
        @file_put_contents($path, implode("\n", $lines), FILE_APPEND);
    }
}
