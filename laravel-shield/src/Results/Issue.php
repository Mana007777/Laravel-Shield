<?php

namespace YourName\LaravelShield\Results;

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
    ) {
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
        ];
    }
}
