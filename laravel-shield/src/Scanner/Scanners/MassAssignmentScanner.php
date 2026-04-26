<?php

namespace YourName\LaravelShield\Scanner\Scanners;

use YourName\LaravelShield\Results\Severity;
use YourName\LaravelShield\ScanContext;
use YourName\LaravelShield\Scanner\BaseScanner;

class MassAssignmentScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'mass';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        foreach ($context->findFiles('app/Models', 'php', true) as $file) {
            $c = (string) @file_get_contents($file);
            if ($c === '' || !str_contains($c, 'Model')) {
                continue;
            }
            if (!preg_match('/extends\s+\\\\?Illuminate\\\\Database\\\\Eloquent\\\\Model\\b/s', $c)) {
                continue;
            }
            $linePublicGuarded = $this->lineMatch($c, '/public\s+\$guarded\s*=\s*\[\s*\]\s*;/');
            if ($linePublicGuarded > 0) {
                $issues[] = $this->makeIssue(
                    $file,
                    $linePublicGuarded,
                    Severity::HIGH,
                    'Public unguarded model',
                    '`public $guarded = []` makes every attribute fillable; prefer `$fillable` or `protected` `$guarded`.',
                    'Use `protected $fillable = […];` for explicit allow-list, or a narrow `protected $guarded`.',
                );
                continue;
            }
            $lineProtectedGuarded = $this->lineMatch($c, '/protected\s+\$guarded\s*=\s*\[\s*\]\s*;/');
            if ($lineProtectedGuarded > 0) {
                $issues[] = $this->makeIssue(
                    $file,
                    $lineProtectedGuarded,
                    Severity::MEDIUM,
                    'Empty `protected $guarded` (fully fillable)',
                    'An empty `guarded` array allows mass assignment of all attributes.',
                    'List explicit fields in `$fillable` for clarity and safer defaults.',
                );
                continue;
            }
            if (!str_contains($c, '$fillable') && !str_contains($c, '$guarded')) {
                $issues[] = $this->makeIssue(
                    $file,
                    $this->lineMatch($c, '/\bclass\s+\w+/') ?: 1,
                    Severity::MEDIUM,
                    'Eloquent model without `$fillable` or `$guarded`',
                    'Laravel 12+ still recommends declaring mass assignment rules explicitly.',
                    'Define `$fillable` or a non-default `$guarded` on every public-facing model.',
                );
            }
        }

        return $this->filterSuppressed($this->getKey(), $issues);
    }

    private function lineMatch(string $content, string $pattern): int
    {
        if (preg_match_all($pattern, $content, $m, PREG_OFFSET_CAPTURE)) {
            if (isset($m[0][0][1])) {
                $off = (int) $m[0][0][1];
                return 1 + substr_count(substr($content, 0, $off), "\n");
            }
        }
        return 0;
    }
}
