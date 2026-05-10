<?php

namespace Marlla3x\LaravelShield\Util;

/**
 * Resolves storage paths for baseline and audit when running inside a Laravel tree vs standalone.
 */
class ShieldPaths
{
    public static function isLaravelAppRoot(string $root): bool
    {
        $r = rtrim(str_replace('\\', '/', $root), '/');

        return is_file($r.'/artisan')
            && (is_dir($r.'/bootstrap') || is_file($r.'/bootstrap/app.php'))
            && is_dir($r.'/app');
    }

    public static function baselineFile(string $projectRoot): string
    {
        $r = rtrim(str_replace('\\', '/', $projectRoot), '/');
        if (self::isLaravelAppRoot($r) && is_dir($r.'/storage')) {
            return $r.'/storage/shield-baseline.json';
        }

        return $r.'/.shield-baseline.json';
    }

    public static function auditLogFile(string $projectRoot): string
    {
        $r = rtrim(str_replace('\\', '/', $projectRoot), '/');
        if (self::isLaravelAppRoot($r) && is_dir($r.'/storage')) {
            return $r.'/storage/shield-audit.jsonl';
        }

        return $r.'/.shield-audit.jsonl';
    }
}
