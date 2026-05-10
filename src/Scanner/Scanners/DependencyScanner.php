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

        try {
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
                    null,
                    'no-composer-lock',
                );
            } else {
                $this->staticAudit($lock, $issues);
            }

            $this->runComposerAudit($context->basePath, $issues);
            $this->checkAbandonedOnPackagist($context, $issues);
            $this->checkLockTracked($context->basePath, $issues);
            $this->checkMinimumStability($context->basePath, $issues);
            if ($context->dependencyUpdateHints) {
                $this->runOutdatedHints($context->basePath, $issues);
            }

            return $this->filterSuppressed($this->getKey(), $this->dedupe($issues));
        } catch (\Throwable $e) {
            return [
                $this->makeIssue(
                    $context->basePath.'/composer.json',
                    1,
                    Severity::MEDIUM,
                    'Dependency scanner encountered an error',
                    $e->getMessage(),
                    'Verify Composer is installed and composer.json is valid.',
                    null,
                    'dependency-scanner-error',
                ),
            ];
        }
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
                null,
                'composer-missing',
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
                    null,
                    'composer-audit-parse',
                );
            }
            return;
        }
        $advisories = $data['advisories'] ?? [];
        if (!is_array($advisories) || $advisories === []) {
            return;
        }
        $flat = [];
        if (array_is_list($advisories)) {
            foreach ($advisories as $adv) {
                if (is_array($adv)) {
                    $flat[] = $adv;
                }
            }
        } else {
            foreach ($advisories as $packageName => $items) {
                if (!is_array($items)) {
                    continue;
                }
                foreach ($items as $adv) {
                    if (!is_array($adv)) {
                        continue;
                    }
                    $adv['_shield_pkg'] = $packageName;
                    $flat[] = $adv;
                }
            }
        }
        $added = false;
        foreach ($flat as $adv) {
            $added = true;
            $packageName = (string) ($adv['packageName'] ?? $adv['_shield_pkg'] ?? 'package');
            $title = (string) ($adv['title'] ?? $adv['cve'] ?? 'Advisory');
            $severityRaw = (string) ($adv['severity'] ?? 'high');
            $severity = $this->mapAdvisorySeverity($severityRaw);
            $cve = (string) ($adv['cve'] ?? '');
            $link = (string) ($adv['link'] ?? '');
            if ($link === '' && isset($adv['sources']) && is_array($adv['sources'])) {
                foreach ($adv['sources'] as $src) {
                    if (is_array($src) && !empty($src['url']) && is_string($src['url'])) {
                        $link = (string) $src['url'];
                        break;
                    }
                }
            }
            $affected = '';
            if (isset($adv['affectedVersions']) && is_string($adv['affectedVersions'])) {
                $affected = $adv['affectedVersions'];
            }
            $fixedHint = $this->extractFixedVersionHint($affected);
            $parts = [];
            $parts[] = $title !== '' ? $title : 'Security advisory';
            $parts[] = 'Severity: '.$severityRaw;
            if ($cve !== '') {
                $parts[] = 'CVE: '.$cve;
            }
            if ($affected !== '') {
                $parts[] = 'Affected versions: '.$affected;
            }
            if ($fixedHint !== '') {
                $parts[] = 'Fixed from: '.$fixedHint;
            }
            if ($link !== '') {
                $parts[] = 'Advisory: '.$link;
            }
            $desc = implode(' · ', array_filter($parts, static fn (string $p) => $p !== ''));
            $issues[] = $this->makeIssue(
                $base.'/composer.lock',
                1,
                $severity,
                'Composer advisory: '.$packageName,
                $desc,
                'Run `composer update` for the affected package or follow the advisory guidance.',
                null,
                'composer-advisory-'.preg_replace('/[^a-z0-9]+/i', '-', $packageName),
            );
        }
        if (!$added) {
            $issues[] = $this->makeIssue(
                $base.'/composer.lock',
                1,
                Severity::HIGH,
                'Composer audit reported advisories',
                'Known vulnerable packages or versions may be installed.',
                'Run `composer audit` in the project, update affected dependencies, and re-run this scan.',
                null,
                'composer-audit-generic',
            );
        }
    }

    private function mapAdvisorySeverity(string $s): Severity
    {
        return match (strtolower($s)) {
            'critical' => Severity::CRITICAL,
            'high' => Severity::HIGH,
            'medium', 'moderate' => Severity::MEDIUM,
            'low' => Severity::LOW,
            default => Severity::HIGH,
        };
    }

    /**
     * Best-effort parse of an upper bound / fixed version from Composer advisory range strings.
     */
    private function extractFixedVersionHint(string $affected): string
    {
        if ($affected === '') {
            return '';
        }
        if (preg_match('/<\s*([0-9][0-9a-zA-Z._-]*)/', $affected, $m)) {
            return $m[1];
        }
        if (preg_match('/,\s*([0-9][0-9a-zA-Z._-]*)\s*$/', $affected, $m)) {
            return $m[1];
        }

        return '';
    }

    private function checkLockTracked(string $base, array &$issues): void
    {
        if (!is_dir($base.'/.git') || !is_file($base.'/composer.lock')) {
            return;
        }
        $p = new Process(['git', 'ls-files', '--error-unmatch', 'composer.lock'], $base, null, null, 10);
        $p->run();
        if ($p->isSuccessful()) {
            return;
        }
        $issues[] = $this->makeIssue(
            $base.'/composer.lock',
            1,
            Severity::MEDIUM,
            '`composer.lock` may not be committed',
            '`git ls-files` did not list composer.lock as tracked.',
            'Commit composer.lock for application deployments.',
            null,
            'composer-lock-untracked',
        );
    }

    private function checkMinimumStability(string $base, array &$issues): void
    {
        $f = $base.'/composer.json';
        if (!is_file($f)) {
            return;
        }
        $j = @json_decode((string) file_get_contents($f), true);
        if (!is_array($j)) {
            return;
        }
        $ms = strtolower((string) ($j['minimum-stability'] ?? 'stable'));
        $prefer = (bool) ($j['prefer-stable'] ?? false);
        if ($ms === 'dev' && !$prefer) {
            $issues[] = $this->makeIssue(
                $f,
                1,
                Severity::MEDIUM,
                '`minimum-stability: dev` without `prefer-stable: true`',
                'Dev stability pulls in unstable dependency versions by default.',
                'Set `prefer-stable: true` or raise minimum-stability.',
                null,
                'composer-minimum-stability',
            );
        }
    }

    private function runOutdatedHints(string $base, array &$issues): void
    {
        $p = new Process(['composer', 'outdated', '--format=json', '--no-interaction'], $base, null, null, 120);
        $p->run();
        $out = $p->getOutput();
        if (trim($out) === '') {
            return;
        }
        $data = @json_decode($out, true);
        if (!is_array($data)) {
            return;
        }
        $installed = $data['installed'] ?? $data;
        if (!is_array($installed)) {
            return;
        }
        foreach ($installed as $pkg) {
            if (!is_array($pkg)) {
                continue;
            }
            $name = (string) ($pkg['name'] ?? '');
            $latest = (string) ($pkg['latest'] ?? '');
            $version = (string) ($pkg['version'] ?? '');
            if ($name === '' || $latest === '' || $version === '') {
                continue;
            }
            $maj = $this->majorLag($version, $latest);
            if ($maj >= 2) {
                $issues[] = $this->makeIssue(
                    $base.'/composer.json',
                    1,
                    Severity::LOW,
                    "Package `{$name}` is {$maj}+ major versions behind",
                    "Installed {$version}, latest {$latest}.",
                    'Plan upgrades to supported major versions for security fixes.',
                    null,
                    'package-major-lag',
                );
            }
        }
    }

    private function majorLag(string $installed, string $latest): int
    {
        $i = $this->majorVersion($installed);
        $l = $this->majorVersion($latest);
        if ($i === null || $l === null) {
            return 0;
        }

        return max(0, $l - $i);
    }

    private function majorVersion(string $v): ?int
    {
        $v = ltrim($v, 'v');
        if (!preg_match('/^(\d+)/', $v, $m)) {
            return null;
        }

        return (int) $m[1];
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
                null,
                'packagist-abandoned',
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
            $s = $i->file.':'.$i->line.':'.$i->title.':'.$i->description;
            if (isset($k[$s])) {
                continue;
            }
            $k[$s] = true;
            $o[] = $i;
        }
        return $o;
    }
}
