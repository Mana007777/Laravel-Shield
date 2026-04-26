<?php

namespace Marlla3x\LaravelShield;

use Marlla3x\LaravelShield\Output\ConsoleReporter;
use Marlla3x\LaravelShield\Output\JsonReporter;
use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\Scanner\ScanManager;
use Symfony\Component\Console\Output\NullOutput;
use Symfony\Component\Console\Output\OutputInterface;

class ScanCommandRunner
{
    public function __construct(
        private ScanManager $manager = new ScanManager(),
    ) {
    }

    /**
     * @return list<string> ordered scanner keys
     */
    public function scannerOrder(): array
    {
        return array_map(
            static fn ($s) => $s->getKey(),
            $this->manager->getScanners()
        );
    }

    public function run(ScanOptions $options, ?OutputInterface $out = null): int
    {
        $out ??= new NullOutput();
        $result = $this->manager->run($options);
        $issues = $this->filterSeverity($result->issues, $options->minSeverity);
        if ($options->format === 'json') {
            $json = new JsonReporter();
            $out->write($json->toJson($result, Version::VERSION, $issues));
            $out->writeln('');
        } else {
            $c = new ConsoleReporter($out);
            $c->printBanner(Version::VERSION, $result->scannedPath);
            $c->printSummary($result, $options, $this->scannerOrder());
            $c->report($result, $options, $issues, $this->scannerOrder());
        }
        if ($options->output !== null && $options->output !== '') {
            $j = (new JsonReporter())->toJson($result, Version::VERSION, $issues);
            @file_put_contents($options->output, $j);
        }
        if ($options->ci) {
            return count($issues) > 0 ? 1 : 0;
        }
        return 0;
    }

    public function runWatch(ScanOptions $options, OutputInterface $out, float $interval = 2.0): int
    {
        $out->writeln('<info>Watch mode: scanning every '.(string) $interval.'s. Ctrl+C to stop.</info>');
        while (true) {
            $r = $this->run($options, $out);
            if ($r !== 0 && $options->ci) {
                return $r;
            }
            usleep((int) ($interval * 1_000_000));
        }
    }

    /**
     * @param list<Issue> $issues
     * @return list<Issue>
     */
    public function filterSeverity(array $issues, ?Severity $min): array
    {
        if ($min === null) {
            return $issues;
        }
        return array_values(array_filter(
            $issues,
            static fn (Issue $i) => $i->severity->atLeast($min)
        ));
    }
}
