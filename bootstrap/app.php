<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use App\Http\Middleware\JwtMiddleware;
use App\Http\Middleware\RoleMiddleware;
use App\Http\Middleware\RefreshTokenMiddleware;
use App\Http\Middleware\SlidingSession;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {

        // Daftarkan middleware HttpOnly Token Authentication
        $middleware->alias([
            //'jwt' => JwtMiddleware::class, // gunakan nama pendek & jelas
            'webjwt' => \App\Http\Middleware\WebJwtMiddleware::class,
            'mobilejwt' => \App\Http\Middleware\MobileJwtMiddleware::class,
        ]);
        

    })
    ->withExceptions(function (Exceptions $exceptions): void {
        //
    })
    ->create();
