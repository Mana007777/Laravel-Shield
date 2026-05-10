<?php

namespace Marlla3x\LaravelShield\Console;

use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanCommandRunner;
use Marlla3x\LaravelShield\ScanOptions;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'scan', description: 'Scan a Laravel app for common security issues')]
class RunScanCommand extends Command
{
    public function __construct(
        private ScanCommandRunner $runner = new ScanCommandRunner(),
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('path', InputArgument::OPTIONAL, 'Path to the Laravel app', '.');
        $this->addOption('format', 'f', InputOption::VALUE_REQUIRED, 'table, json, summary, or github', 'table');
        $this->addOption('severity', null, InputOption::VALUE_REQUIRED, 'Minimum severity: critical, high, medium, low, info');
        $this->addOption('only', null, InputOption::VALUE_REQUIRED, 'Comma-separated scanners');
        $this->addOption('exclude', null, InputOption::VALUE_REQUIRED, 'Comma-separated directories to skip');
        $this->addOption('fix-hints', null, InputOption::VALUE_NONE, 'Show how to fix each issue');
        $this->addOption('ci', null, InputOption::VALUE_NONE, 'Exit 1 if any issues match the scan');
        $this->addOption('output', 'o', InputOption::VALUE_REQUIRED, 'Write JSON report to file');
        $this->addOption('watch', 'w', InputOption::VALUE_NONE, 'Re-run scan periodically (simple polling)');
        $this->addOption('no-score', null, InputOption::VALUE_NONE, 'Do not show security score at the end');
        $this->addOption('diff', null, InputOption::VALUE_NONE, 'Report only findings not in baseline');
        $this->addOption('breakdown', null, InputOption::VALUE_NONE, 'Risk breakdown by file');
        $this->addOption('top', null, InputOption::VALUE_REQUIRED, 'Top N files in breakdown', '10');
        $this->addOption('fix', null, InputOption::VALUE_NONE, 'Apply safe automatic patches');
        $this->addOption('dry-run', null, InputOption::VALUE_NONE, 'Show fixes without writing');
        $this->addOption('no-entropy', null, InputOption::VALUE_NONE, 'Skip entropy secret heuristics');
        $this->addOption('entropy-threshold', null, InputOption::VALUE_REQUIRED, 'Entropy threshold', '4.5');
        $this->addOption('all-projects', null, InputOption::VALUE_NONE, 'Scan configured monorepo projects');
        $this->addOption('interactive', 'i', InputOption::VALUE_NONE, 'Interactive browser after scan');
        $this->addOption('update-hints', null, InputOption::VALUE_NONE, 'Composer outdated major lag hints');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $path = (string) $input->getArgument('path');
        $min = $input->getOption('severity');
        $sev = is_string($min) && $min !== '' ? Severity::fromString($min) : null;
        $only = (string) ($input->getOption('only') ?? '');
        $ex = (string) ($input->getOption('exclude') ?? '');
        $opt = new ScanOptions(
            path: $path,
            format: (string) $input->getOption('format'),
            minSeverity: $sev,
            only: $only === '' ? [] : array_map('trim', explode(',', $only)),
            exclude: $ex === '' ? [] : array_map('trim', explode(',', $ex)),
            fixHints: (bool) $input->getOption('fix-hints'),
            ci: (bool) $input->getOption('ci'),
            output: $input->getOption('output'),
            watch: (bool) $input->getOption('watch'),
            showScore: !$input->getOption('no-score'),
            diff: (bool) $input->getOption('diff'),
            breakdown: (bool) $input->getOption('breakdown'),
            top: max(1, (int) $input->getOption('top')),
            fix: (bool) $input->getOption('fix'),
            fixDryRun: (bool) $input->getOption('dry-run'),
            noEntropy: (bool) $input->getOption('no-entropy'),
            entropyThreshold: (float) $input->getOption('entropy-threshold'),
            allProjects: (bool) $input->getOption('all-projects'),
            interactive: (bool) $input->getOption('interactive'),
            updateHints: (bool) $input->getOption('update-hints'),
        );
        if ($opt->watch) {
            return $this->runner->runWatch($opt, $io, 2.0);
        }
        return $this->runner->run($opt, $io);
    }
}
