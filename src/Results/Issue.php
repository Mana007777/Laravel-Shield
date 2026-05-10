<?php

namespace Marlla3x\LaravelShield\Results;

class Issue
{
    public function __construct(
        public string $file,
        public int $line,
        public Severity $severity,
        public string $title,
        public string $description,
        public string $recommendation,
        public string $scanner,
        public string $risk = '',
        public string $rule = '',
        public ?string $projectLabel = null,
    ) {
        if ($this->rule === '') {
            $this->rule = \Marlla3x\LaravelShield\Util\FindingHasher::deriveRuleFromTitle($this->title);
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'file' => $this->file,
            'line' => $this->line,
            'severity' => $this->severity->label(),
            'title' => $this->title,
            'description' => $this->description,
            'recommendation' => $this->recommendation,
            'scanner' => $this->scanner,
            'risk' => $this->risk,
            'rule' => $this->rule,
            'project' => $this->projectLabel,
        ];
    }
}
