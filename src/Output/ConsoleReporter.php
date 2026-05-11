<?php

namespace Marlla3x\LaravelShield\Output;

use Symfony\Component\Console\Output\OutputInterface;
use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\ScanResult;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\Risk\FileRiskBreakdown;
use Marlla3x\LaravelShield\ScanOptions;
use Marlla3x\LaravelShield\SecurityScore;

class ConsoleReporter
{
    public function __construct(
        private OutputInterface $out,
    ) {
    }

    public function printBanner(string $version, string $path): void
    {
        $this->out->writeln('');
        $this->out->writeln('<info> LARAVEL SHIELD — Security Scanner v'.htmlspecialchars($version, ENT_QUOTES, 'UTF-8').'</info>');
        $this->out->writeln(' <fg=gray>Scanning:</> '.htmlspecialchars($path, ENT_QUOTES, 'UTF-8'));
        $this->out->writeln('');
    }

    /**
     * @param list<string> $scanners ordered keys
     */
    public function printSummary(ScanResult $result, ScanOptions $options, array $scanners, array $issues): void
    {
        if ($options->breakdown) {
            return;
        }
        if (!in_array($options->format, ['summary', 'table'], true)) {
            return;
        }
        $by = [];
        foreach ($issues as $issue) {
            if (!$issue instanceof Issue) {
                continue;
            }
            $by[$issue->scanner] = ($by[$issue->scanner] ?? 0) + 1;
        }
        $map = $this->scannerLabels();
        foreach ($scanners as $key) {
            $n = $by[$key] ?? 0;
            $lab = str_pad(($map[$key] ?? strtoupper($key)), 22);
            $this->out->writeln(sprintf(' <fg=gray>%s</> ........  %d  <fg=gray>issues</>', $lab, $n));
        }
        $this->out->writeln('');
    }

    /**
     * @param list<Issue> $issues
     */
    public function printBreakdown(ScanResult $result, array $issues, ScanOptions $options): void
    {
        $rows = FileRiskBreakdown::aggregate($issues, $result->scannedPath);
        $rows = array_slice($rows, 0, max(1, $options->top));
        $this->out->writeln(' <fg=gray>Controller / File                    Risk Score   Findings</>');
        $this->out->writeln(' <fg=gray>─────────────────────────────────────────────────────────</>');
        foreach ($rows as $r) {
            $file = str_pad(substr($r['file'], 0, 36), 36);
            $score = str_pad((string) $r['score'].'/100', 10, ' ', STR_PAD_LEFT);
            $cnt = (string) $r['count'];
            $this->out->writeln(sprintf(' <info>%s</>  %s  %s', $file, $score, $cnt));
        }
        $this->out->writeln('');
    }

    /**
     * @param list<string> $keys
     * @param list<Issue> $issues
     */
    public function report(ScanResult $result, ScanOptions $options, array $issues, array $keys): void
    {
        if ($options->format === 'summary') {
            if ($options->showScore) {
                $this->out->writeln(SecurityScore::line($issues));
            }
            return;
        }
        if ($options->format !== 'table') {
            return;
        }
        if ($options->breakdown) {
            if ($options->showScore) {
                $this->out->writeln(SecurityScore::line($issues));
            }
            return;
        }

        $buckets = [
            Severity::CRITICAL, Severity::HIGH, Severity::MEDIUM, Severity::LOW, Severity::INFO,
        ];
        foreach ($buckets as $sev) {
            $list = array_values(array_filter($issues, static fn (Issue $i) => $i->severity === $sev));
            if ($list === []) {
                continue;
            }
            $this->out->writeln(' <fg=gray>┌'.str_repeat('─', 64).'┐</>');
            $this->out->writeln(' <fg=gray>│</> '.$this->tagFor($sev).$sev->label().' ('.count($list).')</>'.str_repeat(' ', max(0, 40 - strlen($sev->label()))).' <fg=gray>│</>');
            $this->out->writeln(' <fg=gray>├'.str_repeat('─', 64).'┤</>');
            foreach ($list as $i) {
                $this->out->writeln(' <fg=gray>│</> '.$this->oneLine($i, $options->fixHints).' <fg=gray>│</>');
            }
            $this->out->writeln(' <fg=gray>└'.str_repeat('─', 64).'┘</>');
            $this->out->writeln('');
        }
        if ($options->showScore) {
            $this->out->writeln(SecurityScore::line($issues));
        }
    }

    private function tagFor(Severity $s): string
    {
        return match ($s) {
            Severity::CRITICAL => '<options=bold><fg=red>',
            Severity::HIGH => '<fg=red>',
            Severity::MEDIUM => '<fg=yellow>',
            Severity::LOW => '<fg=cyan>',
            Severity::INFO => '<fg=gray>',
        };
    }

    private function oneLine(Issue $i, bool $fix): string
    {
        $loc = basename($i->file).($i->line > 0 ? ':'.$i->line : '');
        $line = $this->tagFor($i->severity).htmlspecialchars($i->title, ENT_QUOTES, 'UTF-8').'</>  <fg=gray>'.htmlspecialchars($loc, ENT_QUOTES, 'UTF-8').'</>';
        $line .= '  <fg=yellow>Risk: '.htmlspecialchars($i->risk, ENT_QUOTES, 'UTF-8').'</>';
        if ($fix) {
            $line .= '  <info>↳ '.htmlspecialchars($i->recommendation, ENT_QUOTES, 'UTF-8').'</info>';
        }
        return $line;
    }

    /**
     * @return array<string, string>
     */
    private function scannerLabels(): array
    {
        return [
            'env' => 'Environment Scanner',
            'validation' => 'Validation Scanner',
            'livewire' => 'Livewire Security Scanner',
            'sql' => 'SQL Injection Scanner',
            'rce' => 'Command Injection Scanner',
            'ssrf' => 'SSRF Scanner',
            'deserialize' => 'Deserialization Scanner',
            'upload' => 'File Upload Scanner',
            'secrets' => 'Secrets Scanner',
            'cors' => 'CORS Scanner',
            'redirect' => 'Redirect/Traversal Scanner',
            'crypto' => 'Crypto Scanner',
            'jwt' => 'JWT Scanner',
            'api' => 'API Security Scanner',
            'session' => 'Session Security Scanner',
            'headers' => 'Security Headers Scanner',
            'idor' => 'IDOR Scanner',
            'exposure' => 'Public Exposure Scanner',
            'csrf' => 'CSRF Scanner',
            'mass' => 'Mass Assignment Scanner',
            'auth' => 'Authorization Scanner',
            'middleware' => 'Middleware Scanner',
            'xss' => 'XSS Scanner',
            'dependency' => 'Dependency Scanner',
            'debug' => 'Debug Scanner',
        ];
    }
}
