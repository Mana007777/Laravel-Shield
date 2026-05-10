<?php

namespace Marlla3x\LaravelShield;

use Marlla3x\LaravelShield\Audit\ScanAuditLogger;
use Marlla3x\LaravelShield\Baseline\BaselineStore;
use Marlla3x\LaravelShield\Fix\AutoFixEngine;
use Marlla3x\LaravelShield\Interactive\ScanInteractiveBrowser;
use Marlla3x\LaravelShield\Output\ConsoleReporter;
use Marlla3x\LaravelShield\Output\GithubReporter;
use Marlla3x\LaravelShield\Output\JsonReporter;
use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\ScanResult;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\Scanner\ScanManager;
use Marlla3x\LaravelShield\SecurityScore;
use Symfony\Component\Console\Helper\ProgressIndicator;
use Symfony\Component\Console\Output\NullOutput;
use Symfony\Component\Console\Output\OutputInterface;

class ScanCommandRunner
{
    public function __construct(
        private ScanManager $manager = new ScanManager(),
        private ScanAuditLogger $auditLogger = new ScanAuditLogger(),
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
        $isDecorated = method_exists($out, 'isDecorated') ? $out->isDecorated() : false;
        $spinner = null;
        $done = 0;
        $ordered = $this->scannerOrder();
        $enabled = array_values(array_filter(
            $ordered,
            fn (string $key) => $this->shouldRunScanner($options->only, $key)
        ));
        $total = count($enabled);

        if (!$out instanceof NullOutput && !$options->watch && $isDecorated) {
            $spinner = new ProgressIndicator(
                $out,
                null,
                80,
                ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
                '✓'
            );
            $spinner->start('Scanning security scanners...');
        } elseif (!$out instanceof NullOutput && !$options->watch) {
            $out->writeln(sprintf('Scanning %d security scanners...', $total));
        }

        $plans = $this->resolveScanPlans($options);
        $result = $this->runPlans($plans, $options, static function (string $scannerKey) use (&$spinner, &$done, $total, $out): void {
            $done++;
            if ($spinner === null) {
                if (!$out instanceof NullOutput) {
                    $out->writeln(sprintf('[%d/%d] Completed scanner: %s', $done, $total, $scannerKey));
                }
                return;
            }
            $spinner->setMessage('Completed scanner: '.$scannerKey);
            $spinner->advance();
        });

        if ($spinner !== null) {
            $spinner->finish('Scan complete');
        } elseif (!$out instanceof NullOutput && !$options->watch) {
            $out->writeln('Scan complete');
        }

        $issues = $this->filterSeverity($result->issues, $options->minSeverity);
        $baselineCount = 0;
        if ($options->diff) {
            $root = $result->scannedPath;
            $data = BaselineStore::read($root);
            $baselineCount = count($data['hashes']);
            if ($baselineCount === 0) {
                if (!$out instanceof NullOutput) {
                    $out->writeln('<comment>shield: No baseline file found; showing all findings. Run shield:baseline to create one.</comment>');
                }
            } else {
                if (!$out instanceof NullOutput) {
                    $out->writeln(sprintf(
                        '<info>Diffing against baseline (%d known issues). Showing new findings only.</info>',
                        $baselineCount
                    ));
                }
                $issues = BaselineStore::filterNew($root, $issues);
            }
        }

        $fixCount = 0;
        $fixRan = false;
        if ($options->fix || $options->fixDryRun) {
            try {
                $engine = new AutoFixEngine();
                $report = $engine->apply($result->scannedPath, $issues, $options->fixDryRun);
                $fixCount = $report['fixes'];
                $fixRan = $options->fix && !$options->fixDryRun;
                if (!$out instanceof NullOutput) {
                    foreach ($report['messages'] as $msg) {
                        $out->writeln('<comment>'.$msg.'</comment>');
                    }
                    if ($options->fixDryRun) {
                        $out->writeln(sprintf('<info>Dry-run: %d change(s) across project (no files written).</info>', $fixCount));
                    } elseif ($options->fix) {
                        $out->writeln(sprintf(
                            '<info>Fixed %d issue(s) across %d file(s). Backups saved to .shield-backup/</info>',
                            $fixCount,
                            $report['files']
                        ));
                    }
                }
            } catch (\Throwable $e) {
                if (!$out instanceof NullOutput) {
                    $out->writeln('<error>shield: auto-fix failed: '.$e->getMessage().'</error>');
                }
            }
        }

        $format = $options->effectiveFormat();
        $jsonExtra = $this->buildJsonProjectsExtra($plans, $result, $issues);

        if ($format === 'json') {
            $json = new JsonReporter();
            $out->write($json->toJson($result, Version::VERSION, $issues, $options, $jsonExtra));
            $out->writeln('');
        } elseif ($format === 'github') {
            (new GithubReporter())->writeAnnotations($out, $issues);
        } else {
            $c = new ConsoleReporter($out);
            $c->printBanner(Version::VERSION, $result->scannedPath);
            $c->printSummary($result, $options, $this->scannerOrder());
            if ($options->breakdown) {
                $c->printBreakdown($result, $issues, $options);
            }
            $c->report($result, $options, $issues, $this->scannerOrder());
        }

        if ($options->output !== null && $options->output !== '') {
            $j = (new JsonReporter())->toJson($result, Version::VERSION, $issues, $options, $jsonExtra);
            @file_put_contents($options->output, $j);
        }

        $summaryPath = getenv('GITHUB_STEP_SUMMARY') ?: '';
        if ($summaryPath !== '') {
            (new GithubReporter())->appendStepSummary($summaryPath, $result, $issues, Version::VERSION);
        }

        try {
            $this->auditLogger->append($result->scannedPath, $options, $issues, $fixCount, $fixRan);
        } catch (\Throwable) {
        }

        if ($options->interactive && !$out instanceof NullOutput) {
            (new ScanInteractiveBrowser())->run($issues, $result->scannedPath, $out);
        }

        if ($options->ci) {
            if ($options->diff && $baselineCount > 0) {
                return count($issues) > 0 ? 1 : 0;
            }

            return count($issues) > 0 ? 1 : 0;
        }

        return 0;
    }

    /**
     * @param list<ScanOptions> $plans
     * @return array<string, mixed>
     */
    private function buildJsonProjectsExtra(array $plans, ScanResult $merged, array $issues): array
    {
        if (count($plans) <= 1) {
            return [];
        }
        $projects = [];
        foreach ($plans as $plan) {
            $label = $plan->projectLabel ?? 'default';
            $projIssues = array_values(array_filter(
                $issues,
                static fn (Issue $i) => ($i->projectLabel ?? '') === ($plan->projectLabel ?? '')
            ));
            $projects[] = [
                'label' => $label,
                'path' => $plan->path,
                'findings' => count($projIssues),
                'score' => SecurityScore::compute($projIssues),
            ];
        }
        $weights = array_column($projects, 'findings');
        $sumW = array_sum($weights);
        $global = 100;
        if ($sumW > 0) {
            $acc = 0.0;
            foreach ($projects as $p) {
                $w = $p['findings'] > 0 ? $p['findings'] : 1;
                $acc += $p['score'] * $w;
            }
            $global = (int) round($acc / max(1, $sumW));
        } elseif ($projects !== []) {
            $global = (int) round(array_sum(array_column($projects, 'score')) / count($projects));
        }

        return [
            'projects' => $projects,
            'global_score' => $global,
        ];
    }

    /**
     * @return list<ScanOptions>
     */
    private function resolveScanPlans(ScanOptions $options): array
    {
        if (!$options->allProjects) {
            return [$options];
        }
        $map = $options->projectPaths;
        if ($map === [] && \function_exists('config')) {
            try {
                $c = config('shield.projects', []);
                if (is_array($c)) {
                    foreach ($c as $k => $v) {
                        if (is_string($k) && is_string($v) && $v !== '') {
                            $map[$k] = $v;
                        }
                    }
                }
            } catch (\Throwable) {
            }
        }
        if ($map === []) {
            return [$options];
        }
        $base = realpath($options->path) ?: $options->path;
        $out = [];
        foreach ($map as $label => $relPath) {
            $abs = $relPath;
            if ($abs !== '' && !str_starts_with($abs, '/') && !preg_match('#^[A-Za-z]:\\\\#', $abs)) {
                $abs = $base.DIRECTORY_SEPARATOR.str_replace(['/', '\\'], DIRECTORY_SEPARATOR, ltrim($relPath, '/\\'));
            }
            $abs = realpath($abs) ?: $abs;
            $out[] = $options->withPathAndLabel($abs, $label);
        }

        return $out;
    }

    /**
     * @param list<ScanOptions> $plans
     */
    private function runPlans(array $plans, ScanOptions $original, ?callable $afterScanner): ScanResult
    {
        if (count($plans) === 1) {
            return $this->manager->run($plans[0], null, $afterScanner);
        }
        $primary = realpath($original->path) ?: $original->path;
        $merged = new ScanResult($primary);
        foreach ($plans as $plan) {
            $sub = $this->manager->run($plan, null, $afterScanner);
            foreach ($sub->issues as $i) {
                $i->projectLabel = $plan->projectLabel;
                $merged->issues[] = $i;
            }
        }

        return $merged;
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

    /**
     * @param list<string> $only
     */
    private function shouldRunScanner(array $only, string $scannerKey): bool
    {
        if ($only === []) {
            return true;
        }
        $aliases = [
            'mass-assignment' => 'mass',
            'assign' => 'mass',
            'deps' => 'dependency',
            'dependencies' => 'dependency',
            'packages' => 'dependency',
            'mw' => 'middleware',
            'http' => 'middleware',
            'cmd' => 'rce',
            'command' => 'rce',
            'exec' => 'rce',
            'deser' => 'deserialize',
            'uploads' => 'upload',
            'keys' => 'secrets',
            'cross-origin' => 'cors',
            'traversal' => 'redirect',
            'lfi' => 'redirect',
            'cryptography' => 'crypto',
            'tokens' => 'jwt',
            'rest' => 'api',
            'endpoint' => 'api',
            'endpoints' => 'api',
            'cookies' => 'session',
            'http-headers' => 'headers',
            'security-headers' => 'headers',
            'idor-bola' => 'idor',
            'bola' => 'idor',
            'public-files' => 'exposure',
            'leaks' => 'exposure',
        ];
        $toCanon = static function (string $k) use ($aliases): string {
            $k = strtolower($k);
            return $aliases[$k] ?? $k;
        };
        $target = $toCanon($scannerKey);
        foreach ($only as $item) {
            if ($toCanon($item) === $target) {
                return true;
            }
        }
        return false;
    }
}
