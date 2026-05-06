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

        $issues = [];
        foreach (['app/Livewire', 'app/Http/Livewire'] as $dir) {
            foreach ($context->findFiles($dir, 'php', false) as $file) {
                $issues = array_merge($issues, $this->scanLivewireComponent($file));
            }
        }

        return $this->filterSuppressed($this->getKey(), $this->dedupe($issues));
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
                );
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
