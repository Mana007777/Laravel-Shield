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
        $this->addOption('format', 'f', InputOption::VALUE_REQUIRED, 'table, json, or summary', 'table');
        $this->addOption('severity', null, InputOption::VALUE_REQUIRED, 'Minimum severity: critical, high, medium, low, info');
        $this->addOption('only', null, InputOption::VALUE_REQUIRED, 'Comma-separated scanners: env,validation,sql,rce,ssrf,deserialize,upload,secrets,cors,redirect,crypto,jwt,api,csrf,mass,auth,middleware,xss,dependency,debug');
        $this->addOption('exclude', null, InputOption::VALUE_REQUIRED, 'Comma-separated directories to skip');
        $this->addOption('fix-hints', null, InputOption::VALUE_NONE, 'Show how to fix each issue');
        $this->addOption('ci', null, InputOption::VALUE_NONE, 'Exit 1 if any issues match the scan');
        $this->addOption('output', 'o', InputOption::VALUE_REQUIRED, 'Write JSON report to file');
        $this->addOption('watch', 'w', InputOption::VALUE_NONE, 'Re-run scan periodically (simple polling)');
        $this->addOption('no-score', null, InputOption::VALUE_NONE, 'Do not show security score at the end');
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
        );
        if ($opt->watch) {
            return $this->runner->runWatch($opt, $io, 2.0);
        }
        return $this->runner->run($opt, $io);
    }
}
