<?php

namespace YourName\LaravelShield\Scanner;

use YourName\LaravelShield\Results\ScanResult;
use YourName\LaravelShield\ScanContext;
use YourName\LaravelShield\ScanOptions;

class ScanManager
{
    /**
     * @return list<BaseScanner>
     */
    public function getScanners(): array
    {
        return [
            new Scanners\EnvScanner(),
            new Scanners\ValidationScanner(),
            new Scanners\SqlInjectionScanner(),
            new Scanners\CsrfScanner(),
            new Scanners\MassAssignmentScanner(),
            new Scanners\AuthScanner(),
            new Scanners\XssScanner(),
            new Scanners\DependencyScanner(),
            new Scanners\DebugScanner(),
        ];
    }

    public function run(ScanOptions $options, ?ScanContext $context = null): ScanResult
    {
        $path = realpath($options->path) ?: $options->path;
        $exclude = $options->exclude !== [] ? $options->exclude : ['vendor', 'node_modules', 'storage', 'bootstrap/cache', 'tests'];
        $context ??= new ScanContext($path, $exclude, $options->only);

        $result = new ScanResult($path);

        foreach ($this->getScanners() as $scanner) {
            if (!$context->shouldRun($scanner->getKey())) {
                continue;
            }
            $issues = $scanner->scan($context);
            $result->merge($issues);
        }

        return $result;
    }
}
