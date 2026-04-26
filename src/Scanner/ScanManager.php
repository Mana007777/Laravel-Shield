<?php

namespace Marlla3x\LaravelShield\Scanner;

use Marlla3x\LaravelShield\Results\ScanResult;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\ScanOptions;

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
            new Scanners\CommandInjectionScanner(),
            new Scanners\SsrfScanner(),
            new Scanners\InsecureDeserializationScanner(),
            new Scanners\FileUploadScanner(),
            new Scanners\HardcodedSecretsScanner(),
            new Scanners\CorsScanner(),
            new Scanners\OpenRedirectTraversalScanner(),
            new Scanners\CryptoScanner(),
            new Scanners\JwtScanner(),
            new Scanners\ApiSecurityScanner(),
            new Scanners\SessionSecurityScanner(),
            new Scanners\SecurityHeadersScanner(),
            new Scanners\CsrfScanner(),
            new Scanners\MassAssignmentScanner(),
            new Scanners\AuthScanner(),
            new Scanners\MiddlewareScanner(),
            new Scanners\XssScanner(),
            new Scanners\DependencyScanner(),
            new Scanners\DebugScanner(),
        ];
    }

    public function run(ScanOptions $options, ?ScanContext $context = null): ScanResult
    {
        $path = realpath($options->path) ?: $options->path;
        $exclude = $options->exclude !== [] ? $options->exclude : ['vendor', 'node_modules', 'storage', 'bootstrap/cache', 'tests', 'fixtures'];
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
