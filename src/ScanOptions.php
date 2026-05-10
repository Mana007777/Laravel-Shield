<?php

namespace Marlla3x\LaravelShield;

use Marlla3x\LaravelShield\Results\Severity;

class ScanOptions
{
    /**
     * @param array<string, string> $projectPaths label => absolute path (for --all-projects)
     */
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
        public bool $diff = false,
        public bool $breakdown = false,
        public int $top = 10,
        public bool $fix = false,
        public bool $fixDryRun = false,
        public bool $noEntropy = false,
        public float $entropyThreshold = 4.5,
        public bool $allProjects = false,
        public bool $interactive = false,
        public bool $updateHints = false,
        public ?string $projectLabel = null,
        /** @var array<string, string> */
        public array $projectPaths = [],
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

        $projects = [];
        if (isset($a['projects']) && is_array($a['projects'])) {
            foreach ($a['projects'] as $label => $p) {
                if (is_string($label) && is_string($p) && $p !== '') {
                    $projects[$label] = $p;
                }
            }
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
            diff: (bool) ($a['diff'] ?? false),
            breakdown: (bool) ($a['breakdown'] ?? false),
            top: max(1, (int) ($a['top'] ?? 10)),
            fix: (bool) ($a['fix'] ?? false),
            fixDryRun: (bool) ($a['fix_dry_run'] ?? $a['fixDryRun'] ?? false),
            noEntropy: (bool) ($a['no_entropy'] ?? $a['noEntropy'] ?? false),
            entropyThreshold: (float) ($a['entropy_threshold'] ?? $a['entropyThreshold'] ?? 4.5),
            allProjects: (bool) ($a['all_projects'] ?? $a['allProjects'] ?? false),
            interactive: (bool) ($a['interactive'] ?? false),
            updateHints: (bool) ($a['update_hints'] ?? $a['updateHints'] ?? false),
            projectLabel: isset($a['project_label']) ? (string) $a['project_label'] : ($a['projectLabel'] ?? null),
            projectPaths: $projects,
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

    public function effectiveFormat(): string
    {
        $f = $this->format === '' ? 'table' : $this->format;
        if ($f === 'github') {
            return 'github';
        }
        if ($f === 'table'
            && (getenv('GITHUB_ACTIONS') === 'true' || getenv('GITHUB_ACTIONS') === '1')
            && getenv('DISABLE_SHIELD_GITHUB_ANNOTATIONS') !== '1') {
            return 'github';
        }

        return $f;
    }

    public function withPathAndLabel(string $path, ?string $projectLabel): self
    {
        return new self(
            path: $path,
            format: $this->format,
            minSeverity: $this->minSeverity,
            only: $this->only,
            exclude: $this->exclude,
            fixHints: $this->fixHints,
            ci: $this->ci,
            output: $this->output,
            watch: $this->watch,
            showScore: $this->showScore,
            diff: $this->diff,
            breakdown: $this->breakdown,
            top: $this->top,
            fix: $this->fix,
            fixDryRun: $this->fixDryRun,
            noEntropy: $this->noEntropy,
            entropyThreshold: $this->entropyThreshold,
            allProjects: $this->allProjects,
            interactive: $this->interactive,
            updateHints: $this->updateHints,
            projectLabel: $projectLabel,
            projectPaths: $this->projectPaths,
        );
    }
}
