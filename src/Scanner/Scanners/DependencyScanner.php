<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Symfony\Component\Process\Process;
use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class DependencyScanner extends BaseScanner
{
    /** @var array<string, list<string>> known vulnerable ranges (package => patterns) */
    private const KNOWN_RISKS = [
        'laravel/framework' => ['5.5.*', '5.6.10'],
        'symfony/symfony' => [],
    ];

    public function getKey(): string
    {
        return 'dependency';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        $lock = $context->basePath.'/composer.lock';
        if (!is_file($lock)) {
            $issues[] = $this->makeIssue(
                $lock,
                0,
                Severity::INFO,
                'No `composer.lock` in project',
                'Without a lock file, install versions are not reproducible for audit.',
                'Commit `composer.lock` for applications (not for libraries).',
            );
        } else {
            $this->staticAudit($lock, $issues);
        }

        $this->runComposerAudit($context->basePath, $issues);
        $this->checkAbandonedOnPackagist($context, $issues);

        return $this->filterSuppressed($this->getKey(), $this->dedupe($issues));
    }

    private function staticAudit(string $lock, array &$issues): void
    {
        $j = @json_decode((string) file_get_contents($lock), true);
        if (!is_array($j) || !isset($j['packages']) || !is_array($j['packages'])) {
            return;
        }
        foreach ($j['packages'] as $pkg) {
            $n = (string) ($pkg['name'] ?? '');
            $v = (string) ($pkg['version'] ?? '');
            if (isset(self::KNOWN_RISKS[$n]) && $v !== '') {
            }
        }
    }

    private function runComposerAudit(string $base, array &$issues): void
    {
        if (!@is_file($base.'/composer.json') || !@is_file($base.'/composer.lock')) {
            return;
        }
        $p = new Process(['composer', 'audit', '--format=json', '--no-interaction'], $base, null, null, 90);
        $p->run();
        $out = $p->getOutput();
        if (trim($out) === '' && $p->getErrorOutput() !== '') {
            $out = $p->getErrorOutput();
        }
        $err = strtolower($p->getErrorOutput().$p->getOutput());
        if (str_contains($err, 'command not found') || str_contains($err, 'no such file') || $p->getExitCode() === 127) {
            $issues[] = $this->makeIssue(
                $base.'/composer.json',
                1,
                Severity::MEDIUM,
                '`composer` not found for `composer audit`',
                'Composer binary was not available to run a dependency audit.',
                'Install Composer in CI or add SCA; locally run `composer audit` from the app root.',
            );
            return;
        }
        $data = is_string($out) && $out !== '' ? @json_decode($out, true) : null;
        if (!is_array($data)) {
            if (!$p->isSuccessful() && $p->getExitCode() !== 1) {
                $issues[] = $this->makeIssue(
                    $base.'/composer.json',
                    1,
                    Severity::MEDIUM,
                    '`composer audit` could not be parsed',
                    'The audit process returned an unexpected result.',
                    'Upgrade Composer to 2.4+; verify `composer audit` works in your environment.',
                );
            }
            return;
        }
        $advisories = $data['advisories'] ?? $data;
        if (is_array($advisories) && $advisories !== []) {
            $issues[] = $this->makeIssue(
                $base.'/composer.lock',
                1,
                Severity::HIGH,
                'Composer audit reported advisories',
                'Known vulnerable packages or versions may be installed.',
                'Run `composer audit` in the project, update affected dependencies, and re-run this scan.',
            );
        }
    }

    private function checkAbandonedOnPackagist(ScanContext $context, array &$issues): void
    {
        $lock = $context->basePath.'/composer.lock';
        if (!is_file($lock)) {
            return;
        }
        $j = @json_decode((string) file_get_contents($lock), true);
        if (!is_array($j) || !isset($j['packages']) || !is_array($j['packages'])) {
            return;
        }
        $n = 0;
        foreach ($j['packages'] as $pkg) {
            if ($n >= 5) {
                break;
            }
            $name = (string) ($pkg['name'] ?? '');
            if (!preg_match('/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/i', $name)) {
                continue;
            }
            $n++;
            if (!$this->packagistAbandoned($name)) {
                continue;
            }
            $issues[] = $this->makeIssue(
                $lock,
                1,
                Severity::MEDIUM,
                "Packagist marks `{$name}` as abandoned",
                'The package is flagged abandoned on Packagist (limited maintenance).',
                'Migrate to a maintained alternative if possible, or plan for a fork/upgrade path.',
            );
        }
    }

    private function packagistAbandoned(string $name): bool
    {
        $url = 'https://packagist.org/packages/'.strtolower($name).'.json';
        $ctx = stream_context_create(['http' => ['timeout' => 3]]);
        $raw = @file_get_contents($url, false, $ctx);
        if ($raw === false) {
            return false;
        }
        $d = @json_decode($raw, true);
        if (!is_array($d) || !isset($d['package']['abandoned']) || $d['package']['abandoned'] === false) {
            return false;
        }
        return (bool) $d['package']['abandoned'];
    }

    /**
     * @param list<Issue> $issues
     * @return list<Issue>
     */
    private function dedupe(array $issues): array
    {
        $k = [];
        $o = [];
        foreach ($issues as $i) {
            $s = $i->file.':'.$i->title;
            if (isset($k[$s])) {
                continue;
            }
            $k[$s] = true;
            $o[] = $i;
        }
        return $o;
    }
}
