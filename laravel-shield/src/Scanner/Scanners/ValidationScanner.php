<?php

namespace YourName\LaravelShield\Scanner\Scanners;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use YourName\LaravelShield\Results\Issue;
use YourName\LaravelShield\Results\Severity;
use YourName\LaravelShield\ScanContext;
use YourName\LaravelShield\Scanner\BaseScanner;
use YourName\LaravelShield\Util\PhpParserFactory;

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
        (new NodeTraverser())->addVisitor($v)->traverse($ast);

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

        (new NodeTraverser())->addVisitor(new class ($m) extends NodeVisitorAbstract {
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
        })->traverse($node->getStmts() ?? []);

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
