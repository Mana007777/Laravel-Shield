<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;

class FileUploadScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'upload';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        foreach ($context->allPhpFiles() as $file) {
            $lines = $this->readLines($file);
            foreach ($lines as $i => $line) {
                $n = $i + 1;
                if (preg_match('/^\s*(\/\/|#|\/\*|\*)/', ltrim($line))) {
                    continue;
                }

                $uploadSink = preg_match('/->(store|storeAs|putFile|putFileAs|move)\s*\(/i', $line)
                    || preg_match('/move_uploaded_file\s*\(/i', $line);
                if (!$uploadSink) {
                    continue;
                }

                $hasValidation = preg_match('/(validate\(|mimes:|mimetypes:|image|dimensions:|max:|File::types|rules\()/', $line);
                $tainted = preg_match('/file\(|\$_FILES|\$request->file\(/i', $line);
                if ($tainted && !$hasValidation) {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::HIGH,
                        'File upload sink without visible validation',
                        'Upload/write operation appears without nearby type/size/content validation.',
                        'Validate extension + MIME + file signature, enforce size limits, randomize filenames, and store outside web root.',
                    );
                } else {
                    $issues[] = $this->makeIssue(
                        $file,
                        $n,
                        Severity::MEDIUM,
                        'Review file upload handling',
                        'Upload operation detected; ensure robust checks against polyglot and executable files.',
                        'Add strict validation and malware scanning, and prevent direct execution from upload directories.',
                    );
                }
            }
        }

        return $this->filterSuppressed($this->getKey(), $this->dedupe($issues));
    }

    /**
     * @param list<Issue> $issues
     * @return list<Issue>
     */
    private function dedupe(array $issues): array
    {
        $seen = [];
        $out = [];
        foreach ($issues as $i) {
            $k = $i->file.':'.$i->line.':'.$i->title;
            if (isset($seen[$k])) {
                continue;
            }
            $seen[$k] = true;
            $out[] = $i;
        }
        return $out;
    }
}
