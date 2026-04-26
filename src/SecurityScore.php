<?php

namespace Marlla3x\LaravelShield;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;

class SecurityScore
{
    public static function compute(array $issues): int
    {
        $pen = 0;
        foreach ($issues as $i) {
            if (!$i instanceof Issue) {
                continue;
            }
            $pen += match ($i->severity) {
                Severity::CRITICAL => 25,
                Severity::HIGH => 12,
                Severity::MEDIUM => 5,
                Severity::LOW => 1,
                Severity::INFO => 0,
            };
        }
        return max(0, min(100, 100 - $pen));
    }

    public static function line(array $issues): string
    {
        $n = self::compute($issues);
        $color = $n >= 80 ? 'info' : ($n >= 50 ? 'fg=yellow' : 'fg=red');
        return ' <options=bold>Security score:</> <'.$color.'>'.(string) $n.'/100</>';
    }
}
