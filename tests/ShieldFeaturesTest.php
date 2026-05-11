<?php

namespace Marlla3x\LaravelShield\Tests;

use Marlla3x\LaravelShield\Baseline\BaselineStore;
use Marlla3x\LaravelShield\Fix\AutoFixEngine;
use Marlla3x\LaravelShield\Output\ConsoleReporter;
use Marlla3x\LaravelShield\Output\GithubReporter;
use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\ScanResult;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\Risk\FileRiskBreakdown;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\ScanOptions;
use Marlla3x\LaravelShield\Scanner\Scanners\HardcodedSecretsScanner;
use Marlla3x\LaravelShield\Util\ShieldPaths;
use Marlla3x\LaravelShield\Version;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;

class ShieldFeaturesTest extends TestCase
{
    public function test_file_risk_breakdown_lowest_score_first(): void
    {
        $root = '/project';
        $issues = [
            new Issue($root.'/safe.php', 1, Severity::LOW, 'a', 'd', 'r', 'xss', '', 'r1'),
            new Issue($root.'/risky.php', 1, Severity::CRITICAL, 'b', 'd', 'r', 'sql', '', 'r2'),
        ];
        $rows = FileRiskBreakdown::aggregate($issues, $root);
        $this->assertSame('risky.php', $rows[0]['file']);
        $this->assertSame(75, $rows[0]['score']);
        $this->assertSame('safe.php', $rows[1]['file']);
    }

    public function test_baseline_filter_new_only(): void
    {
        $tmp = sys_get_temp_dir().'/shield-bl-'.uniqid();
        mkdir($tmp);
        try {
            $a = new Issue($tmp.'/f.php', 1, Severity::HIGH, 'one', 'd', 'r', 'env', '', 'rule-x');
            $b = new Issue($tmp.'/f.php', 2, Severity::HIGH, 'two', 'd', 'r', 'env', '', 'rule-y');
            $w = BaselineStore::write($tmp, [$a], Version::VERSION);
            $this->assertNotFalse($w);
            $filtered = BaselineStore::filterNew($tmp, [$a, $b]);
            $this->assertCount(1, $filtered);
            $this->assertSame(2, $filtered[0]->line);
        } finally {
            @unlink(ShieldPaths::baselineFile($tmp));
            @rmdir($tmp);
        }
    }

    public function test_github_annotation_maps_severity(): void
    {
        $hi = new Issue('/app/x.php', 3, Severity::HIGH, 'Bad', 'd', 'r', 'csrf', '', 'x');
        $lo = new Issue('/app/y.php', 1, Severity::INFO, 'Note', 'd', 'r', 'env', '', 'n');
        $gr = new GithubReporter();
        $this->assertStringStartsWith('::error file=/app/x.php,line=3,col=1::', $gr->annotationLine($hi));
        $this->assertStringStartsWith('::notice file=/app/y.php,line=1,col=1::', $gr->annotationLine($lo));
    }

    public function test_entropy_scanner_flags_long_literal(): void
    {
        $tmp = sys_get_temp_dir().'/shield-ent-'.uniqid();
        mkdir($tmp);
        try {
            $code = "<?php\n\$apiKey = 'aB9dE2fG8hJ1kL4mN7pQ0rS3tU6vW9xYz';\n";
            file_put_contents($tmp.'/Secretish.php', $code);
            $ctx = new ScanContext($tmp, ['vendor', 'node_modules'], [], 4.0, true, 512000);
            $scanner = new HardcodedSecretsScanner();
            $issues = $scanner->scan($ctx);
            $entropy = array_values(array_filter(
                $issues,
                static fn (Issue $i) => $i->rule === 'high-entropy-string'
            ));
            $this->assertNotEmpty($entropy);
            $this->assertStringContainsString('near variable $apiKey', $entropy[0]->title);
        } finally {
            @unlink($tmp.'/Secretish.php');
            @rmdir($tmp);
        }
    }

    public function test_autofix_dry_run_does_not_create_backup_dir(): void
    {
        $tmp = sys_get_temp_dir().'/shield-fix-'.uniqid();
        mkdir($tmp);
        try {
            file_put_contents($tmp.'/.gitignore', "foo\n");
            $engine = new AutoFixEngine();
            $engine->apply($tmp, [], true);
            $this->assertDirectoryDoesNotExist($tmp.'/.shield-backup');
        } finally {
            @unlink($tmp.'/.gitignore');
            @rmdir($tmp);
        }
    }

    public function test_entropy_skipped_when_no_entropy_flag(): void
    {
        $tmp = sys_get_temp_dir().'/shield-noent-'.uniqid();
        mkdir($tmp);
        try {
            file_put_contents($tmp.'/Plain.php', "<?php\n\$apiKey = 'aaaaaaaaaaaaaaaa';\n");
            $ctx = new ScanContext($tmp, ['vendor', 'node_modules'], [], 4.5, false, 512000);
            $scanner = new HardcodedSecretsScanner();
            $issues = $scanner->scan($ctx);
            $entropy = array_values(array_filter(
                $issues,
                static fn (Issue $i) => $i->rule === 'high-entropy-string'
            ));
            $this->assertSame([], $entropy);
        } finally {
            @unlink($tmp.'/Plain.php');
            @rmdir($tmp);
        }
    }

    public function test_summary_counts_use_filtered_issue_list(): void
    {
        $allIssues = [
            new Issue('/app/a.php', 1, Severity::HIGH, 'A', 'd', 'r', 'env', '', 'r1'),
            new Issue('/app/b.php', 1, Severity::HIGH, 'B', 'd', 'r', 'sql', '', 'r2'),
        ];
        $filtered = [$allIssues[0]];

        $result = new ScanResult('/app', $allIssues);
        $options = new ScanOptions(path: '/app', format: 'table');
        $out = new BufferedOutput();
        $reporter = new ConsoleReporter($out);

        $reporter->printSummary($result, $options, ['env', 'sql'], $filtered);
        $text = $out->fetch();

        $this->assertStringContainsString('Environment Scanner', $text);
        $this->assertStringContainsString('SQL Injection Scanner', $text);
        $this->assertMatchesRegularExpression('/Environment Scanner\s+\.+\s+1\s+issues/', $text);
        $this->assertMatchesRegularExpression('/SQL Injection Scanner\s+\.+\s+0\s+issues/', $text);
    }
}
