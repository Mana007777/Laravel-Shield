<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class SqlInjectionScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'sql';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        $pDb = 'DB';
        $pUn = 'unprepared';
        $pStmt = 'statement|select';

        foreach ($context->allPhpFiles() as $file) {
            $lines = $this->readLines($file);
            $content = (string) @file_get_contents($file);

            foreach ($lines as $i => $line) {
                $n = $i + 1;
                if (preg_match('/^\s*(\/\/|#|\/\*)/', ltrim($line)) || preg_match('/^\s+\*\s/', $line)) {
                    continue;
                }
                if (preg_match('/\b'.$pDb.'::('.$pStmt.')\s*\(/i', $line) && (str_contains($line, '."') || str_contains($line, ".'") || (str_contains($line, '".') && str_contains($line, '$')))) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::CRITICAL,
                        'SQL built with string concatenation',
                        'A DB::statement or DB::select call may concatenate into the SQL string.',
                        'Use bound parameters or the query builder; avoid `.` to append variables into the SQL literal.',
                    );
                }
                if (preg_match('/\b'.$pDb.'::'.$pUn.'\s*\(/i', $line)) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::HIGH,
                        'Database unprepared() call',
                        'Executes a raw string as SQL with no parameterization layer.',
                        'Use bound selects with `?` or the query builder; avoid unprepared for untrusted input.',
                    );
                }
            }

            if (preg_match_all('/(whereRaw|orderByRaw|havingRaw|selectRaw)\s*\(([^)]+)\)/i', $content, $mm, PREG_OFFSET_CAPTURE)) {
                foreach ($mm[0] as $j => $full) {
                    $arg = (string) ($mm[2][$j][0] ?? '');
                    if ($arg === '') {
                        continue;
                    }
                    if (str_contains($arg, '$') && !str_contains($arg, '?')) {
                        $off = (int) $mm[0][$j][1];
                        $lineNo = 1 + substr_count(substr($content, 0, $off), "\n");
                        $issues[] = $this->makeIssue(
                            $file,
                            $lineNo,
                            Severity::HIGH,
                            'Raw SQL fragment with variable, no `?` binding',
                            'A raw `*Raw()` call may embed variables in the SQL string without bind placeholders.',
                            'Use `whereRaw("x = ?", [$v])` or the query builder; never interpolate untrusted data.',
                        );
                    }
                }
            }
        }

        return $this->filterSuppressed($this->getKey(), $this->unique($issues));
    }

    private function unique(array $issues): array
    {
        $k = [];
        $o = [];
        /** @var Issue $i */
        foreach ($issues as $i) {
            $s = $i->file.':'.$i->line.':'.$i->title;
            if (isset($k[$s])) {
                continue;
            }
            $k[$s] = true;
            $o[] = $i;
        }
        return $o;
    }
}
