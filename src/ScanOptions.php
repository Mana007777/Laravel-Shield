<?php

namespace Marlla3x\LaravelShield;

use Marlla3x\LaravelShield\Results\Severity;

class ScanOptions
{
    public function __construct(
        public string $path = '.',
        public string $format = 'table',
        public ?Severity $minSeverity = null,
        public array $only = [],
        public array $exclude = [],
        public bool $fixHints = false,
        public bool $ci = false,
        public ?string $output = null,
        public bool $watch = false,
        public bool $showScore = true,
    ) {
    }

    public static function fromArray(array $a): self
    {
        $ex = is_array($a['exclude'] ?? null) ? $a['exclude'] : self::parseCsv($a['exclude'] ?? '');
        $on = is_array($a['only'] ?? null) ? $a['only'] : self::parseCsv($a['only'] ?? '');

        $min = null;
        if (!empty($a['severity'])) {
            $min = Severity::fromString((string) $a['severity']);
        }

        return new self(
            path: (string) ($a['path'] ?? '.'),
            format: (string) ($a['format'] ?? 'table'),
            minSeverity: $min,
            only: array_map('strtolower', $on),
            exclude: $ex,
            fixHints: (bool) ($a['fix_hints'] ?? $a['fixHints'] ?? false),
            ci: (bool) ($a['ci'] ?? false),
            output: $a['output'] ?? $a['outputFile'] ?? null,
            watch: (bool) ($a['watch'] ?? false),
            showScore: (bool) ($a['show_score'] ?? $a['showScore'] ?? true),
        );
    }

    /**
     * @return list<string>
     */
    private static function parseCsv(string $s): array
    {
        if (trim($s) === '') {
            return [];
        }
        return array_values(array_filter(array_map('trim', explode(',', $s))));
    }
}
