<?php

namespace Marlla3x\LaravelShield\Risk;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;

class FileRiskBreakdown
{
    /**
     * Weighted penalty per prompt (subtracted from 100, floored at 0).
     */
    public static function penalty(Severity $s): int
    {
        return match ($s) {
            Severity::CRITICAL => 25,
            Severity::HIGH => 15,
            Severity::MEDIUM => 8,
            Severity::LOW => 3,
            Severity::INFO => 1,
        };
    }

    /**
     * @param list<Issue> $issues
     * @return list<array{file: string, score: int, count: int}>
     */
    public static function aggregate(array $issues, string $projectRoot): array
    {
        $root = rtrim(str_replace('\\', '/', realpath($projectRoot) ?: $projectRoot), '/');
        $byFile = [];
        foreach ($issues as $i) {
            if (!$i instanceof Issue) {
                continue;
            }
            $file = str_replace('\\', '/', $i->file);
            if ($root !== '' && str_starts_with($file, $root.'/')) {
                $file = substr($file, strlen($root) + 1);
            }
            $byFile[$file] ??= ['pen' => 0, 'count' => 0];
            $byFile[$file]['pen'] += self::penalty($i->severity);
            $byFile[$file]['count']++;
        }
        $rows = [];
        foreach ($byFile as $file => $data) {
            $rows[] = [
                'file' => $file,
                'score' => max(0, 100 - $data['pen']),
                'count' => $data['count'],
            ];
        }
        usort($rows, static fn (array $a, array $b) => $a['score'] <=> $b['score']);

        return $rows;
    }
}
