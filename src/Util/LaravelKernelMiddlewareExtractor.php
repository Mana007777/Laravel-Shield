<?php

namespace Marlla3x\LaravelShield\Util;

use PhpParser\Node;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Name\FullyQualified;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Property;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;

/**
 * Extracts $middleware, $middlewareGroups, $middlewareAliases (or $routeMiddleware) from app/Http/Kernel.php.
 */
class LaravelKernelMiddlewareExtractor
{
    /**
     * @return array{global: list<string>, groups: array<string, list<string>>, aliases: array<string, string>, line: int}|null
     */
    public static function extract(string $kernelPath): ?array
    {
        $c = @file_get_contents($kernelPath);
        if ($c === false) {
            return null;
        }
        $parser = PhpParserFactory::createParser();
        try {
            $ast = $parser->parse($c);
        } catch (\Throwable) {
            return null;
        }
        if ($ast === null) {
            return null;
        }
        $v = new KernelPropertyVisitor();
        $t = new NodeTraverser();
        $t->addVisitor($v);
        $t->traverse($ast);
        if ($v->global === [] && $v->groups === [] && $v->aliases === []) {
            return null;
        }
        return [
            'global' => $v->global,
            'groups' => $v->groups,
            'aliases' => $v->aliases,
            'line' => $v->line,
        ];
    }
}

class KernelPropertyVisitor extends NodeVisitorAbstract
{
    /** @var list<string> */
    public array $global = [];

    /** @var array<string, list<string>> */
    public array $groups = [];

    /** @var array<string, string> */
    public array $aliases = [];

    public int $line = 1;

    public function enterNode(Node $n)
    {
        if (! $n instanceof Property || $n->isStatic()) {
            return null;
        }
        $line = (int) $n->getStartLine();
        foreach ($n->props as $p) {
            if ($p->default === null) {
                continue;
            }
            $pn = $p->name->name;
            if ($pn === 'middleware' && $p->default instanceof Array_) {
                $this->line = $line;
                $this->global = $this->listFromArray($p->default);
            }
            if ($pn === 'middlewareGroups' && $p->default instanceof Array_) {
                $this->groups = $this->groupsFromArray($p->default);
            }
            if (in_array($pn, ['middlewareAliases', 'routeMiddleware'], true) && $p->default instanceof Array_) {
                $this->aliases = $this->aliasesFromArray($p->default);
            }
        }
        return null;
    }

    /** @return list<string> */
    private function listFromArray(Array_ $a): array
    {
        $out = [];
        foreach ($a->items as $it) {
            if ($it === null || $it->key !== null) {
                continue;
            }
            $s = $this->exprString($it->value);
            if ($s !== null) {
                $out[] = $s;
            }
        }
        return $out;
    }

    /**
     * @return array<string, list<string>>
     */
    private function groupsFromArray(Array_ $a): array
    {
        $g = [];
        foreach ($a->items as $it) {
            if ($it === null || $it->key === null) {
                continue;
            }
            $k = $this->keyString($it->key);
            if ($k === null || ! $it->value instanceof Array_) {
                continue;
            }
            $g[$k] = $this->listFromArray($it->value);
        }
        return $g;
    }

    /**
     * @return array<string, string> alias => class
     */
    private function aliasesFromArray(Array_ $a): array
    {
        $m = [];
        foreach ($a->items as $it) {
            if ($it === null || $it->key === null) {
                continue;
            }
            $alias = $this->keyString($it->key);
            if ($alias === null) {
                continue;
            }
            $s = $this->exprString($it->value);
            if ($s !== null) {
                $m[$alias] = $s;
            }
        }
        return $m;
    }

    private function keyString(Node\Expr $k): ?string
    {
        if ($k instanceof String_) {
            return $k->value;
        }
        if ($k instanceof Node\Scalar\LNumber) {
            return (string) $k->value;
        }
        return null;
    }

    private function exprString(Node\Expr $e): ?string
    {
        if ($e instanceof String_) {
            return $e->value;
        }
        if (! $e instanceof ClassConstFetch) {
            return null;
        }
        if (! $e->name instanceof Node\Identifier) {
            return null;
        }
        if (strtolower($e->name->name) !== 'class') {
            return null;
        }
        if ($e->class instanceof Node\Name || $e->class instanceof FullyQualified) {
            return ltrim($e->class->toString(), '\\').'::class';
        }
        return null;
    }
}
