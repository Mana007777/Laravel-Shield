<?php

namespace YourName\LaravelShield\Results;

class ScanResult
{
    /**
     * @param list<Issue> $issues
     */
    public function __construct(
        public string $scannedPath,
        public array $issues = [],
    ) {
    }

    public function addIssue(Issue $issue): void
    {
        $this->issues[] = $issue;
    }

    /**
     * @param list<Issue> $issues
     */
    public function merge(array $issues): void
    {
        foreach ($issues as $issue) {
            $this->issues[] = $issue;
        }
    }

    /**
     * @return list<Issue>
     */
    public function getIssuesBySeverity(Severity $min): array
    {
        return array_values(array_filter(
            $this->issues,
            static fn (Issue $i) => $i->severity->atLeast($min)
        ));
    }

    public function countByScanner(): array
    {
        $map = [];
        foreach ($this->issues as $i) {
            $map[$i->scanner] = ($map[$i->scanner] ?? 0) + 1;
        }
        ksort($map);
        return $map;
    }
}
