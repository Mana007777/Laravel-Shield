<?php

namespace Marlla3x\LaravelShield\Scanner\Scanners;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use Marlla3x\LaravelShield\Results\Issue;
use Marlla3x\LaravelShield\Results\Severity;
use Marlla3x\LaravelShield\ScanContext;
use Marlla3x\LaravelShield\Scanner\BaseScanner;
use Marlla3x\LaravelShield\Util\PhpParserFactory;

class ValidationScanner extends BaseScanner
{
    public function getKey(): string
    {
        return 'validation';
    }

    public function scan(ScanContext $context): array
    {
        if (!$context->shouldRun($this->getKey())) {
            return [];
        }

        $issues = [];
        foreach ($context->findFiles('app/Http/Controllers', 'php', true) as $file) {
            if (!str_contains(basename($file), 'Controller')) {
                continue;
            }
            $issues = array_merge($issues, $this->parseControllerFile($file));
        }
        foreach (['app/Livewire', 'app/Http/Livewire'] as $livewireDir) {
            foreach ($context->findFiles($livewireDir, 'php', false) as $file) {
                $issues = array_merge($issues, $this->parseLivewireFile($file));
            }
        }

        return $this->filterSuppressed($this->getKey(), $issues);
    }

    /**
     * @return list<Issue>
     */
    private function parseControllerFile(string $file): array
    {
        $code = @file_get_contents($file);
        if ($code === false) {
            return [];
        }
        $parser = PhpParserFactory::createParser();
        try {
            $ast = $parser->parse($code);
        } catch (\Throwable) {
            return [];
        }
        if ($ast === null) {
            return [];
        }

        $v = new ControllerValidationVisitor();
        $t = new NodeTraverser();
        $t->addVisitor($v);
        $t->traverse($ast);

        $out = [];
        foreach ($v->candidates as $c) {
            if ($c->formRequest) {
                continue;
            }
            if ($c->validate) {
                continue;
            }
            if (! $c->hasIlluminateRequest) {
                continue;
            }
            if ($c->inputAccess) {
                $out[] = $this->makeIssue(
                    $file,
                    $c->line,
                    Severity::HIGH,
                    'Request input without validation',
                    "Method `{$c->name}()` uses input accessors but no `validate()` call or FormRequest was detected.",
                    'Use a FormRequest type-hint or call `$this->validate()` / `$request->validate()`.',
                );
            } elseif (in_array(strtolower($c->name), ['store', 'update', 'create'], true)) {
                $out[] = $this->makeIssue(
                    $file,
                    $c->line,
                    Severity::HIGH,
                    "Action `{$c->name}` has no visible validation",
                    "Methods `store`, `update`, and `create` should use validation or a FormRequest.",
                    'Add a FormRequest or `validate()` with appropriate rules.',
                );
            }
        }

        return $out;
    }

    /**
     * @return list<Issue>
     */
    private function parseLivewireFile(string $file): array
    {
        $code = (string) @file_get_contents($file);
        if ($code === '') {
            return [];
        }
        if (!str_contains($code, 'extends Component') && !str_contains($code, 'Livewire\\Component')) {
            return [];
        }

        $lines = preg_split("/\R/", $code) ?: [];
        $out = [];
        $actionNames = ['save', 'update', 'store', 'create', 'submit', 'delete'];

        foreach ($lines as $idx => $line) {
            if (!preg_match('/public\s+function\s+([a-zA-Z_]\w*)\s*\(/', $line, $m)) {
                continue;
            }
            $method = strtolower($m[1]);
            if (!in_array($method, $actionNames, true)) {
                continue;
            }

            $chunk = $this->methodChunk($lines, $idx);
            $mutatesData = (bool) preg_match('/(::create\(|->(?:create|update|fill|forceFill|save|delete|insert|upsert)\()/', $chunk);
            $hasValidation = str_contains($chunk, 'validate(') || str_contains($chunk, '$rules');

            if ($mutatesData && !$hasValidation) {
                $out[] = $this->makeIssue(
                    $file,
                    $idx + 1,
                    Severity::HIGH,
                    'Livewire state mutation without validation',
                    "Livewire action `{$m[1]}()` appears to write/update data without visible validation.",
                    'Run `$this->validate()` (or a dedicated validator/form object) before create/update/save operations.',
                    'Unvalidated Livewire-bound input can lead to mass assignment, data tampering, or persistent XSS when stored content is later rendered.',
                );
            }
        }

        return $out;
    }

    /**
     * @param list<string> $lines
     */
    private function methodChunk(array $lines, int $start): string
    {
        $chunk = [];
        for ($i = $start; $i < count($lines); $i++) {
            if ($i > $start && preg_match('/^\s*(public|protected|private)\s+function\s+/', $lines[$i])) {
                break;
            }
            $chunk[] = $lines[$i];
        }
        return implode("\n", $chunk);
    }
}

/** @internal */
class MethodScan
{
    public function __construct(
        public string $name,
        public int $line,
        public bool $hasIlluminateRequest = false,
        public bool $formRequest = false,
        public bool $validate = false,
        public bool $inputAccess = false,
    ) {
    }
}

class ControllerValidationVisitor extends NodeVisitorAbstract
{
    /**
     * @var list<MethodScan>
     */
    public array $candidates = [];

    public function enterNode(Node $node)
    {
        if (!$node instanceof ClassMethod) {
            return null;
        }
        if (!$node->isPublic() || $node->isStatic()) {
            return null;
        }
        if (str_starts_with($node->name->toString(), '__')) {
            return null;
        }
        if ($node->getStmts() === null) {
            return null;
        }

        $m = new MethodScan(
            $node->name->toString(),
            (int) $node->getStartLine(),
        );

        foreach ($node->getParams() as $p) {
            $tn = $this->paramTypeName($p);
            if ($tn === null) {
                continue;
            }
            if (!str_ends_with($tn, 'Request')) {
                continue;
            }
            if ($this->isDefaultHttpRequest($tn)) {
                $m->hasIlluminateRequest = true;
            } else {
                $m->formRequest = true;
            }
        }

        if (! $m->hasIlluminateRequest && ! $m->formRequest) {
            return null;
        }
        if ($m->formRequest) {
            $this->candidates[] = $m;
            return null;
        }

        $inner = new class ($m) extends NodeVisitorAbstract {
            public function __construct(private MethodScan $m)
            {
            }

            public function enterNode(Node $n)
            {
                if ($n instanceof Node\Expr\MethodCall) {
                    $this->methodCall($n);
                } elseif ($n instanceof Node\Expr\FuncCall) {
                    $name = $n->name;
                    if ($name instanceof Node\Name && $name->toString() === 'validate') {
                        $this->m->validate = true;
                    }
                }
            }

            private function methodCall(MethodCall $n): void
            {
                $mname = $n->name;
                if ($mname instanceof Node\Identifier) {
                    $nstr = $mname->toString();
                    if (in_array($nstr, ['input', 'get', 'all', 'inputAll', 'query'], true)) {
                        $this->m->inputAccess = true;
                    }
                    if (in_array($nstr, ['validate', 'validateWith', 'validateWithBag', 'validateResolved'], true)) {
                        $this->m->validate = true;
                    }
                }
            }
        };
        $t2 = new NodeTraverser();
        $t2->addVisitor($inner);
        $t2->traverse($node->getStmts() ?? []);

        $this->candidates[] = $m;
        return null;
    }

    private function paramTypeName(Node\Param $p): ?string
    {
        $t = $p->type;
        if ($t === null) {
            return null;
        }
        if ($t instanceof Node\Name) {
            return $t->toString();
        }
        if ($t instanceof Node\Name\FullyQualified) {
            return $t->toString();
        }
        if ($t instanceof Node\NullableType) {
            $in = $t->type;
            if ($in instanceof Node\Name) {
                return $in->toString();
            }
            if ($in instanceof Node\Name\FullyQualified) {
                return $in->toString();
            }
        }
        return null;
    }

    private function isDefaultHttpRequest(string $t): bool
    {
        return in_array($t, [
            'Request',
            'Illuminate\\Http\\Request',
            'Symfony\\Component\\HttpFoundation\\Request',
        ], true);
    }
}
