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
            new Scanners\LivewireSecurityScanner(),
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
            new Scanners\IdorScanner(),
            new Scanners\PublicExposureScanner(),
            new Scanners\CsrfScanner(),
            new Scanners\MassAssignmentScanner(),
            new Scanners\AuthScanner(),
            new Scanners\MiddlewareScanner(),
            new Scanners\XssScanner(),
            new Scanners\DependencyScanner(),
            new Scanners\DebugScanner(),
        ];
    }

    public function run(ScanOptions $options, ?ScanContext $context = null, ?callable $afterScanner = null): ScanResult
    {
        $path = realpath($options->path) ?: $options->path;
        $exclude = $options->exclude !== [] ? $options->exclude : ['vendor', 'node_modules', 'storage', 'bootstrap/cache', 'tests', 'fixtures'];
        $maxEntropy = 512000;
        if (\function_exists('config')) {
            try {
                $c = config('shield.max_entropy_file_bytes');
                if ($c !== null) {
                    $maxEntropy = (int) $c;
                }
            } catch (\Throwable) {
                // No Laravel container (standalone tests / binary)
            }
        }
        $context ??= new ScanContext(
            $path,
            $exclude,
            $options->only,
            entropyThreshold: $options->entropyThreshold,
            entropyEnabled: !$options->noEntropy,
            maxEntropyFileBytes: $maxEntropy,
            dependencyUpdateHints: $options->updateHints,
        );

        $result = new ScanResult($path);

        foreach ($this->getScanners() as $scanner) {
            if (!$context->shouldRun($scanner->getKey())) {
                continue;
            }
            $issues = $scanner->scan($context);
            $result->merge($issues);
            if ($afterScanner !== null) {
                $afterScanner($scanner->getKey());
            }
        }

        return $result;
    }
}
