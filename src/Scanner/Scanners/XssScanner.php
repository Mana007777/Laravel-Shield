<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class XssScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'xss';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        foreach ($context->allBladeFiles() as $f) {
            $lines = $this->readLines($f);
            foreach ($lines as $i => $line) {
                $n = $i + 1;
                if (preg_match('/\{!!\s*\$[^!]+\s*!!\}/', $line) || (str_contains($line, '{!!') && str_contains($line, '!!}') && str_contains($line, '$') && !str_contains($line, '@json'))) {
                    if (str_contains($line, '{!!--')) {
                        continue;
                    }
                    if (str_contains($line, '$request') && str_contains($line, '{!!')) {
                        $issues[] = $this->makeIssue(
                            $f,
                            $n,
                            Severity::CRITICAL,
                            'Unescaped Blade output of request/user data',
                            '`{!! !!}` with dynamic data can render HTML/JS in the page.',
                            'Escape with `{{ }}` or pre-sanitize; never echo raw user input in `{!!`.',
                        );
                    } else {
                        $issues[] = $this->makeIssue(
                            $f,
                            $n,
                            Severity::HIGH,
                            'Unescaped Blade output with variables',
                            '`{!! !!}` prints raw HTML; dangerous if the value includes user data.',
                            'Prefer `{{ }}` or `e()`; only use `{!!` for trusted, sanitized HTML.',
                        );
                    }
                }
                if (preg_match("/echo\\s*\\\$request->input\(|echo\\s*\\\$request\[/", $line)) {
                    $issues[] = $this->makeIssue(
                        $f,
                        $n,
                        Severity::CRITICAL,
                        'Echo of request data in a view',
                        'Raw output of `echo $request` input can be XSS if echoed into HTML without escaping.',
                        'Use `{{ }}` in Blade, or `e()`; validate and encode for the output context.',
                    );
                }
            }
        }
        $php = $context->findFiles('resources/views', 'php', false);
        foreach ($php as $f) {
            if (str_ends_with($f, '.blade.php')) {
                continue;
            }
            $c = (string) @file_get_contents($f);
            if (str_contains($c, 'echo $request->input(') || str_contains($c, "echo @\$request->input(")) {
                $issues[] = $this->makeIssue(
                    $f,
                    $this->lineOfString($c, 'echo $request->input('),
                    Severity::CRITICAL,
                    'PHP view echoes request input',
                    'Echoing request values can cause XSS in HTML/JS context.',
                    'Escape output: `e()` or Blade `{{`.',
                );
            }
        }

        return $this->filterSuppressed($this->getKey(), $issues);
    }

    private function lineOfString(string $c, string $s): int
    {
        $p = stripos($c, $s);
        if ($p === false) {
            return 1;
        }
        return 1 + substr_count(substr($c, 0, $p), "\n");
    }
}
