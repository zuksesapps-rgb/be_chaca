<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Admin\AdminController;
use App\Http\Controllers\User\UserController;
use App\Http\Controllers\User\GoogleController as UserGoogleController;

// =============
// PUBLIC ROUTES
// =============
Route::prefix('user/auth')->group(function () {
    Route::post('login', [UserController::class, 'login'])->middleware('throttle:10,5');
    Route::post('register', [UserController::class, 'register']);

    // 🚀 Refresh token harus publik (tidak pakai middleware!)
    Route::get('refresh', [UserController::class, 'refresh']);
});


// ====================================
// PROTECTED ROUTES (JWT COOKIE WEB)
// ====================================
Route::middleware('webjwt:api_user')->group(function () {
    Route::prefix('user/auth')->group(function () {
        Route::post('/update', [UserController::class, 'update']);
        Route::get('/me', [UserController::class, 'me']);
        Route::get('/users', [UserController::class, 'show']);
        Route::put('/users{id}', [UserController::class, 'update']);
        Route::delete('/users{id}', [UserController::class, 'detele']);
        Route::get('/logout', [UserController::class, 'logout']);

    });
});


// GOOGLE OAUTH
Route::get('/auth/google/redirect', [UserGoogleController::class, 'redirect']);
Route::get('/auth/google/callback', [UserGoogleController::class, 'callback']);
