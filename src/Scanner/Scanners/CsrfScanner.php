<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class CsrfScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'csrf';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        $web = $context->basePath.'/routes/web.php';
        if (is_file($web)) {
            $c = (string) file_get_contents($web);
            if (str_contains($c, 'VerifyCsrfToken') && str_contains($c, 'withoutMiddleware')) {
                $issues[] = $this->makeIssue(
                    $web,
                    $this->lineOf($c, 'withoutMiddleware'),
                    Severity::HIGH,
                    'CSRF middleware removed on a route',
                    'A route may call `withoutMiddleware(VerifyCsrfToken::class)` and skip CSRF protection.',
                    'Do not disable CSRF for state-changing `web` routes unless you have an equivalent token check.',
                );
            }
        }

        $verify = $this->findVerifyCsrfFile($context);
        if (is_file($verify)) {
            $vc = (string) file_get_contents($verify);
            if (preg_match('/\$except\s*=\s*\[([^\]]*)\]/s', $vc, $m)) {
                $inner = trim($m[1] ?? '');
                if ($inner !== '' && $inner !== '/*' && !str_contains($inner, '/*') && strlen($inner) < 2000) {
                    if (!preg_match('/^\s*\/\//', $inner) && (str_contains($inner, "'") || str_contains($inner, '"'))) {
                        $issues[] = $this->makeIssue(
                            $verify,
                            $this->lineOf($vc, '$except'),
                            Severity::HIGH,
                            '`VerifyCsrfToken::$except` is non-empty',
                            'The CSRF verify middleware whitelists URL patterns; they must not be abused for state-changing web forms.',
                            'Review every entry; prefer fixing clients or using signed routes instead of broad `except` rules.',
                        );
                    }
                }
            }
        }

        foreach ($context->allBladeFiles() as $blade) {
            $b = (string) file_get_contents($blade);
            if (!str_contains($b, '<form')) {
                continue;
            }
            if ($this->formStateChanging($b) && ! $this->formHasToken($b)) {
                $issues[] = $this->makeIssue(
                    $blade,
                    $this->firstFormLine($b),
                    Severity::HIGH,
                    'Form missing CSRF token',
                    'A state-changing form does not use `@csrf` or a hidden `_token` field.',
                    'Add `@csrf` inside the `<form>` (or a hidden `csrf` field) for all POST/PUT/PATCH/DELETE forms.',
                );
            }
        }

        return $this->filterSuppressed($this->getKey(), $issues);
    }

    private function findVerifyCsrfFile(ScanContext $c): string
    {
        $p1 = $c->basePath.'/app/Http/Middleware/VerifyCsrfToken.php';
        if (is_file($p1)) {
            return $p1;
        }
        return $c->basePath.'/app/Http/Middleware/ValidateCsrfToken.php';
    }

    private function lineOf(string $content, string $needle): int
    {
        $p = stripos($content, $needle);
        if ($p === false) {
            return 1;
        }
        return 1 + substr_count(substr($content, 0, $p), "\n");
    }

    private function formStateChanging(string $b): bool
    {
        if (!str_contains($b, '<form')) {
            return false;
        }
        if (str_contains($b, '@method(')) {
            return true;
        }
        if (preg_match('/<form[^>]*\bmethod\s*=\s*["\']?(get|head)/i', $b) && !preg_match('/<form[^>]+method=\\s*["\']?post|put|delete|patch/i', $b)) {
            return false;
        }
        if (preg_match('/<form[^>]*\bmethod\s*=\s*["\']?(post|put|delete|patch)/i', $b)) {
            return true;
        }
        if (preg_match('/<form(?![^>]*\bmethod=)\s*[^>]*>/i', $b)) {
            return false;
        }
        return false;
    }

    private function formHasToken(string $b): bool
    {
        if (str_contains($b, '@csrf')) {
            return true;
        }
        if (preg_match('/name=\\s*["\']_token["\']/', $b) || str_contains($b, 'csrf_token()')) {
            return true;
        }
        if (str_contains($b, '@honeypot') && str_contains($b, '_token')) {
            return true;
        }
        return false;
    }

    private function firstFormLine(string $b): int
    {
        if (preg_match('/<form/i', $b, $m, PREG_OFFSET_CAPTURE)) {
            return 1 + substr_count(substr($b, 0, (int) $m[0][1]), "\n");
        }
        return 1;
    }
}
