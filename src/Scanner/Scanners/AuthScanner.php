<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class AuthScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'auth';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = $this->scanRoutesForUnauthenticatedPaths($context);
        $issues = array_merge($issues, $this->checkControllersForAuthorize($context));

        return $this->filterSuppressed($this->getKey(), $this->dedupe($issues));
    }

    /**
     * @return list<Issue>
     */
    private function scanRoutesForUnauthenticatedPaths(ScanContext $context): array
    {
        $out = [];
        foreach (['routes/web.php', 'routes/api.php'] as $rel) {
            $p = $context->basePath.'/'.$rel;
            if (!is_file($p)) {
                continue;
            }
            $lines = $this->readLines($p);
            $inAuthGroup = false;
            $groupDepth = 0;
            foreach ($lines as $i => $line) {
                if (str_contains($line, "Route::group") && (str_contains($line, "'auth'") || str_contains($line, '"auth"') || str_contains($line, 'auth:') || str_contains($line, 'auth:sanctum'))) {
                    $inAuthGroup = true;
                }
                if (str_contains($line, 'Route::group(')) {
                    $groupDepth++;
                }
                if (preg_match('/\}\s*\);?\s*$/', $line) && $groupDepth > 0) {
                    $groupDepth--;
                }
                if (preg_match('/Route::(get|post|put|patch|delete|any|view|resource)\s*\(\s*[\[\'\"]/i', $line) === 0) {
                    continue;
                }
                if (! preg_match("~['\"](/[^'\"]*(?:/admin|/dashboard|/user/|/settings|/profile|/backend|admin))~i", $line)) {
                    continue;
                }
                if ($this->lineHasAuthMiddleware($line) || $inAuthGroup) {
                    continue;
                }
                if (str_contains($line, '//') && (stripos($line, 'route::') > stripos($line, '//'))) {
                    continue;
                }
                $out[] = $this->makeIssue(
                    $p,
                    $i + 1,
                    Severity::HIGH,
                    'Sensitive route may lack authentication middleware',
                    'This route path looks admin/user-facing, but the line has no `auth` / `auth:api` / `auth:sanctum` in the call.',
                    "Wrap the route in `Route::middleware('auth'…` or a group, or add `->middleware('auth')` if appropriate.",
                );
            }
        }
        return $out;
    }

    private function lineHasAuthMiddleware(string $line): bool
    {
        if (preg_match("/middleware\(\s*[\[\'\"]?auth|->middleware\(\s*[\[\'\"]auth|auth:api|auth:sanctum|auth:web|auth:password|middleware'\s*=>\s*'auth'|middleware'\\s*=>\\s*\\[\\s*'auth'/i", $line)) {
            return true;
        }
        if (str_contains($line, "['middleware' => ['auth") || str_contains($line, 'middleware" => "auth"')) {
            return true;
        }
        return false;
    }

    /**
     * @return list<Issue>
     */
    private function checkControllersForAuthorize(ScanContext $context): array
    {
        $out = [];
        foreach ($context->findFiles('app/Http/Controllers', 'php', true) as $file) {
            if (!str_ends_with($file, 'Controller.php')) {
                continue;
            }
            $c = (string) @file_get_contents($file);
            if (preg_match_all('/function\s+(store|update|create|destroy|edit)\s*\(/i', $c, $m, PREG_OFFSET_CAPTURE)) {
                if (empty($m[0])) {
                    continue;
                }
                foreach ($m[0] as $idx => $row) {
                    $off = (int) $m[0][$idx][1];
                    $name = (string) ($m[1][$idx][0] ?? 'action');
                    $block = $this->methodBlockFromOffset($c, $off);
                    if ($block === null) {
                        continue;
                    }
                    if (str_contains($block, 'authorize(') || str_contains($block, '->authorize(') || str_contains($block, 'Gate::') || str_contains($block, '->can(')) {
                        continue;
                    }
                    if (str_contains($block, "middleware('can:") || str_contains($block, 'can:')) {
                        continue;
                    }
                    if (str_contains($block, "abort(403") || str_contains($block, 'deny()')) {
                        continue;
                    }
                    $line = 1 + substr_count(substr($c, 0, $off), "\n");
                    $out[] = $this->makeIssue(
                        $file,
                        $line,
                        Severity::MEDIUM,
                        "`{$name}()` may lack `authorize()`",
                        'A resource action was found that does not call `authorize()` or a gate; policies may be missing.',
                        'Add `$this->authorize()` or `Gate::` checks for model actions.',
                    );
                }
            }
        }
        return $out;
    }

    private function methodBlockFromOffset(string $c, int $nameOffset): ?string
    {
        $p = $nameOffset;
        $l = strlen($c);
        while ($p < $l && $c[$p] !== '{') {
            $p++;
        }
        if ($p >= $l) {
            return null;
        }
        $d = 0;
        for ($i = $p; $i < $l; $i++) {
            if ($c[$i] === '{') {
                $d++;
            } elseif ($c[$i] === '}') {
                $d--;
                if ($d === 0) {
                    return substr($c, $p, $i - $p + 1);
                }
            }
        }
        return null;
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
