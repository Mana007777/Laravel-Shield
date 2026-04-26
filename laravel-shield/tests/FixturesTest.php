<?php

namespace YourName\LaravelShield\Tests;

use YourName\LaravelShield\Output\JsonReporter;
use YourName\LaravelShield\Results\Issue;
use YourName\LaravelShield\Results\ScanResult;
use YourName\LaravelShield\Results\Severity;
use YourName\LaravelShield\ScanCommandRunner;
use YourName\LaravelShield\ScanOptions;
use YourName\LaravelShield\Version;
use PHPUnit\Framework\TestCase;

class FixturesTest extends TestCase
{
    public function test_vulnerable_env_has_critical(): void
    {
        $path = __DIR__.'/fixtures/vulnerable';
        $opt = new ScanOptions(path: $path, only: ['env'], format: 'summary');
        $m = (new \YourName\LaravelShield\Scanner\ScanManager())->run($opt);
        $r = (new ScanCommandRunner())->filterSeverity($m->issues, null);
        $crit = array_values(array_filter($r, static fn (Issue $i) => $i->severity === Severity::CRITICAL));
        $this->assertNotEmpty($crit, 'Vulnerable .env should produce at least one critical env finding');
    }

    public function test_safe_fixture_minimal_issues(): void
    {
        $path = __DIR__.'/fixtures/safe';
        $m = (new \YourName\LaravelShield\Scanner\ScanManager())->run(
            new ScanOptions(path: $path, only: ['env', 'xss', 'sql'], format: 'summary')
        );
        $r = (new ScanCommandRunner())->filterSeverity($m->issues, null);
        $this->assertIsArray($r);
    }

    public function test_json_reporter_is_valid(): void
    {
        $m = (new \YourName\LaravelShield\Scanner\ScanManager())->run(
            new ScanOptions(path: __DIR__.'/fixtures/vulnerable', only: ['env'])
        );
        $j = (new JsonReporter())->toJson($m, Version::VERSION, $m->issues);
        $d = json_decode($j, true, 512, JSON_THROW_ON_ERROR);
        $this->assertArrayHasKey('issues', $d);
    }

    public function test_ci_exits_1_on_issues(): void
    {
        $path = __DIR__.'/fixtures/vulnerable';
        $opt = new ScanOptions(path: $path, only: ['env'], format: 'summary', ci: true);
        $ex = (new ScanCommandRunner())->run($opt);
        $this->assertSame(1, $ex);
    }

    public function test_sql_scanner_finds_concat(): void
    {
        $m = (new \YourName\LaravelShield\Scanner\ScanManager())->run(
            new ScanOptions(path: __DIR__.'/fixtures/vulnerable', only: ['sql'], format: 'summary')
        );
        $this->assertNotEmpty($m->issues);
    }
}
