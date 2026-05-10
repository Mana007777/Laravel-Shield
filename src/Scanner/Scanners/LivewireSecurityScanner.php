<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class LivewireSecurityScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'livewire';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        try {
            $issues = [];
            foreach (['app/Livewire', 'app/Http/Livewire'] as $dir) {
                foreach ($context->findFiles($dir, 'php', false) as $file) {
                    $issues = array_merge($issues, $this->scanLivewireComponent($file));
                }
            }
            $issues = array_merge($issues, $this->scanVoltAndBladeLivewire($context));

            return $this->filterSuppressed($this->getKey(), $this->dedupe($issues));
        } catch (\Throwable $e) {
            return [
                $this->makeIssue(
                    $context->basePath,
                    1,
                    Severity::MEDIUM,
                    'Livewire scanner encountered an error',
                    $e->getMessage(),
                    'Re-run with a clean checkout or report a bug if this persists.',
                    null,
                    'livewire-scanner-error',
                ),
            ];
        }
    }

    /**
     * @return list<Issue>
     */
    private function scanVoltAndBladeLivewire(ScanContext $context): array
    {
        $issues = [];
        foreach (['resources/views/livewire', 'resources/views/components'] as $sub) {
            $dir = $context->basePath.'/'.$sub;
            if (!is_dir($dir)) {
                continue;
            }
            $it = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
            );
            foreach ($it as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                $path = $file->getPathname();
                if (!str_ends_with($path, '.php') && !str_ends_with($path, '.blade.php')) {
                    continue;
                }
                $issues = array_merge($issues, $this->scanLivewireComponent($path));
                $issues = array_merge($issues, $this->scanVoltPatterns($path));
            }
        }

        return $issues;
    }

    /**
     * @return list<Issue>
     */
    private function scanVoltPatterns(string $file): array
    {
        $code = (string) @file_get_contents($file);
        if ($code === '') {
            return [];
        }
        $issues = [];
        $lines = preg_split("/\R/", $code) ?: [];
        foreach ($lines as $i => $line) {
            $n = $i + 1;
            if (preg_match('/\b(state|computed)\s*\(\s*function\s*\([^)]*\)\s*\{[^}]*auth\s*\(\s*\)\s*->\s*user\s*\(/i', $line)
                && !str_contains($line, 'authorize') && !str_contains($line, 'Gate::')) {
                $issues[] = $this->makeIssue(
                    $file,
                    $n,
                    Severity::MEDIUM,
                    'Volt state/computed references `auth()->user()` without visible guard',
                    'Ensure authorization runs before exposing user-derived state.',
                    'Add `$this->authorize(...)` or policy checks in the closure.',
                    null,
                    'volt-auth-guard',
                );
            }
            if (preg_match('/wire:model(?!\.defer)\s*=\s*["\'][^"\']*(?:password|token|secret)/i', $line)) {
                $issues[] = $this->makeIssue(
                    $file,
                    $n,
                    Severity::HIGH,
                    'Sensitive `wire:model` binding without defer',
                    'Password/token fields should use `wire:model.defer` or server-only handling.',
                    'Switch to `wire:model.defer` and validate server-side.',
                    null,
                    'livewire-sensitive-model',
                );
            }
        }
        if (preg_match('/#\[Computed\][\s\S]{0,800}?\$(?:password|secret|token|ssn)/i', $code)
            && !str_contains($code, 'authorize(')) {
            $issues[] = $this->makeIssue(
                $file,
                1,
                Severity::HIGH,
                '`#[Computed]` may expose sensitive attributes',
                'Computed properties are exposed to the client; verify authorization.',
                'Authorize before exposing model attributes; avoid sensitive fields.',
                null,
                'livewire-computed-sensitive',
            );
        }
        if (preg_match('/#\[On\s*\(/i', $code)) {
            foreach (['save', 'delete', 'update', 'destroy', 'create'] as $verb) {
                if (preg_match('/#\[On[^\]]+\][\s\S]{0,1200}?function\s+\w+\s*\([^)]*\)\s*\{[^}]*\$this->'.$verb.'\s*\(/i', $code)
                    && !str_contains($code, 'authorize(')) {
                    $issues[] = $this->makeIssue(
                        $file,
                        1,
                        Severity::HIGH,
                        '`#[On]` listener may perform state changes without authorization',
                        'Event handlers that mutate data should call `authorize()`.',
                        'Add `$this->authorize(...)` at the start of the handler.',
                        null,
                        'livewire-on-unauth',
                    );
                    break;
                }
            }
        }
        if (preg_match('/\$this->(?:dispatch|emit)\s*\([^)]*(?:password|token|secret|ssn)/i', $code)) {
            $issues[] = $this->makeIssue(
                $file,
                1,
                Severity::MEDIUM,
                '`dispatch()` / `emit()` may broadcast sensitive data',
                'Event payloads can reach parent components or the browser.',
                'Avoid dispatching secrets; use server-side-only channels.',
                null,
                'livewire-dispatch-sensitive',
            );
        }

        return $issues;
    }

    /**
     * @return list<Issue>
     */
    private function scanLivewireComponent(string $file): array
    {
        $code = (string) @file_get_contents($file);
        if ($code === '') {
            return [];
        }
        if (!str_contains($code, 'extends Component') && !str_contains($code, 'Livewire\\Component')) {
            return [];
        }

        $issues = [];
        $lines = preg_split("/\R/", $code) ?: [];
        $sensitivePublicProps = ['is_admin', 'isAdmin', 'role', 'roles', 'permission', 'permissions', 'user_id', 'account_id', 'balance', 'price'];

        foreach ($lines as $i => $line) {
            $n = $i + 1;
            if (preg_match('/^\s*(\/\/|#|\/\*|\*)/', ltrim($line))) {
                continue;
            }

            if (preg_match('/public\s+[\?\w\\\\|]+\s+\$(\w+)/', $line, $m)) {
                $prop = $m[1];
                if (in_array($prop, $sensitivePublicProps, true)) {
                    $prev = $lines[$i - 1] ?? '';
                    if (!str_contains($prev, '#[Locked]')) {
                        $issues[] = $this->makeIssue(
                            $file,
                            $n,
                            Severity::HIGH,
                            'Potentially sensitive Livewire public property is not locked',
                            "Public property `\${$prop}` may be client-mutable without a Livewire lock/guard.",
                            'Use `#[Locked]` for non-client-mutable properties and enforce authorization in mutating actions.',
                            'Tampering with sensitive Livewire state can lead to privilege escalation or unauthorized data changes.',
                        );
                    }
                }
            }
        }

        if (str_contains($code, 'WithFileUploads')) {
            if (!str_contains($code, 'validate(') && !str_contains($code, '$rules')) {
                $issues[] = $this->makeIssue(
                    $file,
                    1,
                    Severity::HIGH,
                    'Livewire file uploads detected without visible validation rules',
                    'Livewire file upload capability appears enabled but no obvious validation rule usage was found.',
                    'Validate type/size/signature and store files on private disk with randomized names.',
                    'Unvalidated uploads can enable malware hosting, content confusion attacks, and sensitive data exposure.',
                );
            }
        }

        foreach (['save', 'store', 'update', 'delete', 'destroy', 'submit'] as $method) {
            if (!preg_match('/public\s+function\s+'.$method.'\s*\(/i', $code, $m, PREG_OFFSET_CAPTURE)) {
                continue;
            }
            $offset = (int) $m[0][1];
            $block = $this->methodBlockFromOffset($code, $offset);
            if ($block === null) {
                continue;
            }
            $line = 1 + substr_count(substr($code, 0, $offset), "\n");
            $mutates = (bool) preg_match('/(::create\(|->(?:save|update|delete|forceFill|fill|insert|upsert)\()/', $block);
            $hasAuthz = str_contains($block, 'authorize(') || str_contains($block, 'Gate::') || str_contains($block, '->can(');
            if ($mutates && !$hasAuthz) {
                $issues[] = $this->makeIssue(
                    $file,
                    $line,
                    Severity::HIGH,
                    'Livewire mutating action has no visible authorization',
                    "Method `{$method}()` appears to modify persistent state without clear authorize/policy checks.",
                    'Call `$this->authorize(...)` or `Gate::authorize(...)` before mutating data.',
                    'Missing authorization checks in Livewire actions can permit IDOR-style unauthorized updates or deletes.',
                    null,
                    'livewire-mutate-unauth',
                );
            }
        }

        if (preg_match('/wire:click\s*=\s*["\'][^"\']+/', $code)) {
            if (preg_match('/wire:click\s*=\s*["\'](\w+)/', $code, $wm)) {
                $handler = $wm[1];
                if ($handler !== '' && preg_match('/public\s+function\s+'.$handler.'\s*\(/i', $code, $hm, PREG_OFFSET_CAPTURE)) {
                    $off = (int) $hm[0][1];
                    $blk = $this->methodBlockFromOffset($code, $off);
                    if ($blk !== null) {
                        $ln = 1 + substr_count(substr($code, 0, $off), "\n");
                        $writes = (bool) preg_match('/->(?:save|update|delete|create)\(/', $blk);
                        $hasAuthz = str_contains($blk, 'authorize(');
                        if ($writes && !$hasAuthz) {
                            $issues[] = $this->makeIssue(
                                $file,
                                $ln,
                                Severity::MEDIUM,
                                '`wire:click` target performs writes without visible `authorize()`',
                                "Method `{$handler}()` may persist data without authorization checks.",
                                'Authorize before database writes in Livewire actions.',
                                null,
                                'livewire-click-unauth',
                            );
                        }
                    }
                }
            }
        }

        return $issues;
    }

    private function methodBlockFromOffset(string $code, int $nameOffset): ?string
    {
        $p = $nameOffset;
        $l = strlen($code);
        while ($p < $l && $code[$p] !== '{') {
            $p++;
        }
        if ($p >= $l) {
            return null;
        }
        $d = 0;
        for ($i = $p; $i < $l; $i++) {
            if ($code[$i] === '{') {
                $d++;
            } elseif ($code[$i] === '}') {
                $d--;
                if ($d === 0) {
                    return substr($code, $p, $i - $p + 1);
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
        $seen = [];
        $out = [];
        foreach ($issues as $i) {
            $k = $i->file.':'.$i->line.':'.$i->title;
            if (isset($seen[$k])) {
                continue;
            }
            $seen[$k] = true;
            $out[] = $i;
        }
        return $out;
    }
}
