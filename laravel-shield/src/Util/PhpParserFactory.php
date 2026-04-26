<?php

namespace YourName\LaravelShield\Util;

class PhpParserFactory
{
    public static function createParser(): \PhpParser\Parser
    {
        if (method_exists(\PhpParser\ParserFactory::class, 'createForNewestSupportedVersion')) {
            return (new \PhpParser\ParserFactory)->createForNewestSupportedVersion();
        }

        return (new \PhpParser\ParserFactory)->create(
            \PhpParser\ParserFactory::PREFER_PHP7
        );
    }
}
