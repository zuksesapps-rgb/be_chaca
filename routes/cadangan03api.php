<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Admin\AdminController as AdminController;
use App\Http\Controllers\User\UserController;
use App\Http\Controllers\User\GoogleController as UserGoogleController;

Route::prefix('admin')->group(function () {
    Route::prefix('auth')->group(function () {
        Route::post('login', [AdminController::class, 'login']); 
        // Route::post('login', [AdminController::class, 'login'])->middleware('throttle:5,1');
        Route::post('register', [AdminController::class, 'register']); 
    });
});

Route::prefix('user')->group(function () {
    Route::prefix('auth')->group(function () {
        Route::post('login', [UserController::class, 'login'])->middleware('throttle:10,5');
        Route::post('login_mobile', [UserController::class, 'login_mobile']); 
        Route::post('register', [UserController::class, 'register']); 
        Route::post('send-otp', [UserController::class, 'sendOtp']); 
        Route::post('verify-otp', [UserController::class, 'verifyOtp']); 
        Route::post('create-account', [UserController::class, 'createAccount']); 
    });
});
    //createAccount

Route::middleware(['mobilejwt:api_admin', 'throttle:60,1'])->group(function () {
    Route::prefix('admin')->group(function () {
        Route::prefix('auth')->group(function () {
            Route::get('/me', [AdminController::class, 'me']);
            Route::get('/users', [AdminController::class, 'show']);
            Route::put('/users{id}', [AdminController::class, 'update']);
            Route::delete('/users{id}', [AdminController::class, 'detele']);
            Route::get('/logout', [AdminController::class, 'logout']);

        });
    });

});

//atau

Route::middleware('mobilejwt:api_admin')->group(function () {
    Route::prefix('admin')->group(function () {
        Route::prefix('auth')->middleware('throttle:60,1')->group(function () {
            Route::get('/me', [AdminController::class, 'me']);
            Route::get('/users', [AdminController::class, 'show']);
            Route::put('/users{id}', [AdminController::class, 'update']);
            Route::delete('/users{id}', [AdminController::class, 'detele']);
            Route::get('/logout', [AdminController::class, 'logout']);
        });
    });
});


Route::middleware('mobilejwt:api_user')->group(function () {
    // Buyer order
    Route::prefix('user')->group(function () {
        Route::prefix('auth')->group(function () {
            Route::get('/me', [UserController::class, 'me']);      
            Route::get('/users', [UserController::class, 'show']); 
            Route::put('/users{id}', [UserController::class, 'update']);
            Route::delete('/users{id}', [UserController::class, 'detele']);
            Route::get('/refresh', [UserController::class, 'refresh']);
            Route::get('/logout', [UserController::class, 'logout']);
        });
    });
});


Route::get('/auth/google/redirect', [UserGoogleController::class, 'redirect']);
Route::get('/auth/google/callback', [UserGoogleController::class, 'callback']);