<?php

namespace Marlla3x\LaravelShield\Util;

use Marlla3x\LaravelShield\Results\Issue;

class FindingHasher
{
    /**
     * Stable hash for baseline/diff: scanner, relative path, line, rule.
     */
    public static function hash(Issue $issue, string $projectRoot): string
    {
        $root = rtrim(str_replace('\\', '/', realpath($projectRoot) ?: $projectRoot), '/');
        $file = str_replace('\\', '/', $issue->file);
        $rel = $file;
        if ($root !== '' && str_starts_with($file, $root.'/')) {
            $rel = substr($file, strlen($root) + 1);
        }

        $payload = json_encode(
            [
                $issue->scanner,
                $rel,
                $issue->line,
                $issue->rule !== '' ? $issue->rule : self::deriveRuleFromTitle($issue->title),
            ],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES
        );

        return hash('sha256', $payload);
    }

    public static function deriveRuleFromTitle(string $title): string
    {
        $s = strtolower(trim($title));
        $s = preg_replace('/[^a-z0-9]+/', '-', $s) ?? '';
        $s = trim((string) $s, '-');

        return $s !== '' ? $s : 'finding';
    }
}
