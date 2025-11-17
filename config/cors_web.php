<?php

namespace App\Http\Middleware;

use Closure;

class WebCors
{
    public function handle($request, Closure $next)
    {
        return $next($request)
            ->header('Access-Control-Allow-Origin', 'http://localhost:3000') // domain Next.js
            ->header('Access-Control-Allow-Credentials', 'true') // ❗ WAJIB untuk HttpOnly cookie
            ->header('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-TOKEN')
            ->header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    }
}
