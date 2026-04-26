<?php

namespace App\Http\Middleware;

class WeakHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->header('X-Frame-Options', 'ALLOWALL');
        $response->header('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'");
        return $response;
    }
}

