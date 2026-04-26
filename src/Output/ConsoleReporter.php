<?php

namespace Marlla3x\LaravelShield\Output;

use Symfony\Component\Console\Output\OutputInterface;
use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\ScanResult;
use Marlla3x\LaravelShield\Results\Severity;
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
    public function printSummary(ScanResult $result, ScanOptions $options, array $scanners): void
    {
        if (!in_array($options->format, ['summary', 'table'], true)) {
            return;
        }
        $by = $result->countByScanner();
        $map = $this->scannerLabels();
        foreach ($scanners as $key) {
            $n = $by[$key] ?? 0;
            $lab = str_pad('['.($map[$key] ?? strtoupper($key)).']', 12);
            $this->out->writeln(sprintf(' <fg=gray>%s</> ........  %d  <fg=gray>issues</>', $lab, $n));
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
            'env' => 'ENV',
            'validation' => 'VALID',
            'sql' => 'SQL',
            'rce' => 'RCE',
            'ssrf' => 'SSRF',
            'deserialize' => 'DESER',
            'upload' => 'UPLOAD',
            'secrets' => 'SECRETS',
            'cors' => 'CORS',
            'redirect' => 'REDIRECT',
            'crypto' => 'CRYPTO',
            'jwt' => 'JWT',
            'api' => 'API',
            'session' => 'SESSION',
            'headers' => 'HEADERS',
            'csrf' => 'CSRF',
            'mass' => 'MASS',
            'auth' => 'AUTH',
            'middleware' => 'MW',
            'xss' => 'XSS',
            'dependency' => 'DEPS',
            'debug' => 'DEBUG',
        ];
    }
}
