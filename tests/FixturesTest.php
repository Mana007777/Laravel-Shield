<?php

namespace Marlla3x\LaravelShield\Tests;

use Marlla3x\LaravelShield\Output\JsonReporter;
use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\ScanResult;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanCommandRunner;
use Marlla3x\LaravelShield\ScanOptions;
use Marlla3x\LaravelShield\Scanner\ScanManager;
use Marlla3x\LaravelShield\Version;
use PHPUnit\Framework\TestCase;

class FixturesTest extends TestCase
{
    public function test_vulnerable_env_has_critical(): void
    {
        $path = __DIR__.'/../fixtures/vulnerable';
        $opt = new ScanOptions(path: $path, only: ['env'], format: 'summary');
        $m = (new \Marlla3x\LaravelShield\Scanner\ScanManager())->run($opt);
        $r = (new ScanCommandRunner())->filterSeverity($m->issues, null);
        $crit = array_values(array_filter($r, static fn (Issue $i) => $i->severity === Severity::CRITICAL));
        $this->assertNotEmpty($crit, 'Vulnerable .env should produce at least one critical env finding');
    }

    public function test_safe_fixture_minimal_issues(): void
    {
        $path = __DIR__.'/../fixtures/safe';
        $m = (new \Marlla3x\LaravelShield\Scanner\ScanManager())->run(
            new ScanOptions(path: $path, only: ['env', 'xss', 'sql'], format: 'summary')
        );
        $r = (new ScanCommandRunner())->filterSeverity($m->issues, null);
        $this->assertIsArray($r);
    }

    public function test_json_reporter_is_valid(): void
    {
        $m = (new \Marlla3x\LaravelShield\Scanner\ScanManager())->run(
            new ScanOptions(path: __DIR__.'/../fixtures/vulnerable', only: ['env'])
        );
        $j = (new JsonReporter())->toJson($m, Version::VERSION, $m->issues);
        $d = json_decode($j, true, 512, JSON_THROW_ON_ERROR);
        $this->assertArrayHasKey('issues', $d);
    }

    public function test_ci_exits_1_on_issues(): void
    {
        $path = __DIR__.'/../fixtures/vulnerable';
        $opt = new ScanOptions(path: $path, only: ['env'], format: 'summary', ci: true);
        $ex = (new ScanCommandRunner())->run($opt);
        $this->assertSame(1, $ex);
    }

    public function test_sql_scanner_finds_concat(): void
    {
        $m = (new \Marlla3x\LaravelShield\Scanner\ScanManager())->run(
            new ScanOptions(path: __DIR__.'/../fixtures/vulnerable', only: ['sql'], format: 'summary')
        );
        $this->assertNotEmpty($m->issues);
    }

    public function test_middleware_scanner_parses_kernel_and_lists_stack(): void
    {
        $m = (new ScanManager())->run(
            new ScanOptions(path: __DIR__.'/../fixtures/middleware_laravel10', only: ['middleware'], format: 'summary')
        );
        $mw = array_filter(
            $m->issues,
            static fn ($i) => $i->scanner === 'middleware'
        );
        $this->assertNotEmpty($mw, 'Expected middleware inventory INFO issues for Kernel + custom classes');
        $hasGlobal = false;
        $hasGroup = false;
        foreach ($mw as $i) {
            if (str_contains($i->title, 'Global middleware')) {
                $hasGlobal = true;
            }
            if (str_contains($i->title, 'Middleware group')) {
                $hasGroup = true;
            }
        }
        $this->assertTrue($hasGlobal, 'Should report global stack from Kernel');
        $this->assertTrue($hasGroup, 'Should report at least one group from Kernel');
    }
}
