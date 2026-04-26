<?php

namespace YourName\LaravelShield\Scanner;

use YourName\LaravelShield\Results\Issue;
use YourName\LaravelShield\Results\Severity;
use YourName\LaravelShield\ScanContext;

abstract class BaseScanner
{
    abstract public function getKey(): string;

    /**
     * @return list<Issue>
     */
    abstract public function scan(ScanContext $context): array;

    protected function makeIssue(
        string $file,
        int $line,
        Severity $severity,
        string $title,
        string $description,
        string $recommendation,
    ): Issue {
        return new Issue(
            $file,
            $line,
            $severity,
            $title,
            $description,
            $recommendation,
            $this->getKey(),
        );
    }

    /**
     * @return list<string> lines
     */
    protected function readLines(string $file): array
    {
        $c = @file_get_contents($file);
        if ($c === false) {
            return [];
        }
        return preg_split("/\R/", $c) ?: [];
    }

    protected function isSuppressedAtLine(string $file, int $line, string $scannerKey): bool
    {
        $lines = $this->readLines($file);
        $i = $line - 1;
        for ($d = 0; $d <= 2; $d++) {
            $check = $i - $d;
            if ($check < 0) {
                break;
            }
            $l = $lines[$check] ?? '';
            if (preg_match('/@shield-ignore-next-line|shield:ignore|@shield\\s*ignore/i', $l)) {
                if (preg_match('/shield:ignore\\s*:\\s*([a-z,\\s-]+)/i', $l, $m)) {
                    $ids = array_map('trim', explode(',', $m[1]));
                    if (in_array($scannerKey, $ids, true) || in_array('all', $ids, true)) {
                        return true;
                    }
                } elseif (preg_match('/@shield-ignore-next-line|shield:ignore(?!\\s*:)/i', $l)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @param list<Issue> $issues
     * @return list<Issue>
     */
    protected function filterSuppressed(string $scannerKey, array $issues): array
    {
        $out = [];
        foreach ($issues as $i) {
            if (!$this->isSuppressedAtLine($i->file, $i->line, $scannerKey)) {
                $out[] = $i;
            }
        }
        return $out;
    }
}
