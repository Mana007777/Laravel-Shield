<?php

namespace Marlla3x\LaravelShield\Commands;

use Illuminate\Console\Command;

class ConfigDiffCommand extends Command
{
    protected $signature = 'shield:config-diff
        {path? : Project root}';

    protected $description = 'Compare Laravel config against security-hardening recommendations';

    public function handle(): int
    {
        $root = rtrim((string) ($this->argument('path') ?: base_path()), '/\\');
        $rows = [];
        try {
            $rows = array_merge($rows, $this->checkSession($root));
            $rows = array_merge($rows, $this->checkAuth($root));
            $rows = array_merge($rows, $this->checkCors($root));
            $rows = array_merge($rows, $this->checkHashing($root));
            $rows = array_merge($rows, $this->checkSanctum($root));
            $rows = array_merge($rows, $this->checkLogging($root));
        } catch (\Throwable $e) {
            $this->warn('shield:config-diff: '.$e->getMessage());
        }
        if ($rows === []) {
            $this->info('No config drift issues detected (or config files missing).');

            return 0;
        }
        $this->line('Config Key | Current Value | Recommended Value | Risk');
        $this->line(str_repeat('-', 76));
        foreach ($rows as $r) {
            $this->line(sprintf(
                '%s | %s | %s | %s',
                $r['key'],
                $r['current'],
                $r['recommended'],
                $r['risk']
            ));
        }

        return count($rows) > 0 ? 0 : 0;
    }

    /**
     * @return list<array{key: string, current: string, recommended: string, risk: string}>
     */
    private function checkSession(string $root): array
    {
        $f = $root.'/config/session.php';
        if (!is_file($f)) {
            return [];
        }
        $out = [];
        $c = (string) file_get_contents($f);
        if (preg_match("/'secure'\\s*=>\\s*(false|0)\\b/", $c)) {
            $out[] = [
                'key' => 'session.secure',
                'current' => 'false',
                'recommended' => 'true (over HTTPS)',
                'risk' => 'medium',
            ];
        }
        if (preg_match("/'same_site'\\s*=>\\s*env\s*\(/i", $c)) {
            // env-driven; skip static drift check
        } elseif (preg_match("/'same_site'\\s*=>\\s*['\"]([^'\"]+)['\"]/i", $c, $sm)) {
            $sv = strtolower(trim($sm[1]));
            if (!in_array($sv, ['lax', 'strict'], true)) {
                $out[] = [
                    'key' => 'session.same_site',
                    'current' => $sm[1],
                    'recommended' => 'strict or lax',
                    'risk' => 'medium',
                ];
            }
        }
        if (preg_match("/'lifetime'\\s*=>\\s*(\\d+)/", $c, $m) && (int) $m[1] > 120) {
            $out[] = [
                'key' => 'session.lifetime',
                'current' => $m[1].' min',
                'recommended' => '<= 120',
                'risk' => 'low',
            ];
        }

        return $out;
    }

    /**
     * @return list<array{key: string, current: string, recommended: string, risk: string}>
     */
    private function checkAuth(string $root): array
    {
        $f = $root.'/config/auth.php';
        if (!is_file($f)) {
            return [];
        }
        $c = (string) file_get_contents($f);
        if (preg_match("/'expire'\\s*=>\\s*(\\d+)/", $c, $m) && (int) $m[1] > 60) {
            return [[
                'key' => 'auth.passwords.users.expire',
                'current' => $m[1].' min',
                'recommended' => '<= 60',
                'risk' => 'medium',
            ]];
        }

        return [];
    }

    /**
     * @return list<array{key: string, current: string, recommended: string, risk: string}>
     */
    private function checkCors(string $root): array
    {
        $f = $root.'/config/cors.php';
        if (!is_file($f)) {
            return [];
        }
        $c = (string) file_get_contents($f);
        if (preg_match('/supports_credentials\s*=>\s*true/', $c)
            && (str_contains($c, "'*'") || str_contains($c, '"*"') || str_contains($c, 'allowed_origins: [\'*\']'))) {
            return [[
                'key' => 'cors',
                'current' => 'wildcard origins + credentials',
                'recommended' => 'explicit origins',
                'risk' => 'high',
            ]];
        }

        return [];
    }

    /**
     * @return list<array{key: string, current: string, recommended: string, risk: string}>
     */
    private function checkHashing(string $root): array
    {
        $f = $root.'/config/hashing.php';
        if (!is_file($f)) {
            return [];
        }
        $c = (string) file_get_contents($f);
        $out = [];
        if (preg_match("/'rounds'\\s*=>\\s*(\\d+)/", $c, $m) && (int) $m[1] < 12) {
            $out[] = [
                'key' => 'hashing.bcrypt.rounds',
                'current' => $m[1],
                'recommended' => '>= 12',
                'risk' => 'medium',
            ];
        }
        if (preg_match("/'memory'\\s*=>\\s*(\\d+)/", $c, $m) && (int) $m[1] < 65536) {
            $out[] = [
                'key' => 'hashing.argon.memory',
                'current' => $m[1],
                'recommended' => '>= 65536',
                'risk' => 'medium',
            ];
        }

        return $out;
    }

    /**
     * @return list<array{key: string, current: string, recommended: string, risk: string}>
     */
    private function checkSanctum(string $root): array
    {
        $f = $root.'/config/sanctum.php';
        if (!is_file($f)) {
            return [];
        }
        $c = (string) file_get_contents($f);
        if (preg_match('/stateful\s*=>\s*\[(.*?)\]/s', $c, $m) && strlen($m[1]) > 80) {
            return [[
                'key' => 'sanctum.stateful',
                'current' => 'long domain list',
                'recommended' => 'minimal explicit hosts',
                'risk' => 'low',
            ]];
        }

        return [];
    }

    /**
     * @return list<array{key: string, current: string, recommended: string, risk: string}>
     */
    private function checkLogging(string $root): array
    {
        $f = $root.'/config/logging.php';
        if (!is_file($f)) {
            return [];
        }
        $c = (string) file_get_contents($f);
        if (str_contains($c, 'slack') && !preg_match("/'level'\\s*=>\\s*['\"]critical['\"]/", $c)) {
            return [[
                'key' => 'logging.channels',
                'current' => 'slack driver without strict level',
                'recommended' => 'cap level (e.g. critical) for external sinks',
                'risk' => 'medium',
            ]];
        }

        return [];
    }
}
