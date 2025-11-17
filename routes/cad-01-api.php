<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;


Route::post('/login', [UserController::class, 'login']);
Route::post('/login_mobile', [UserController::class, 'login_mobile']);
Route::post('/register', [UserController::class, 'register']);

Route::middleware('jwt')->group(function () {
    Route::get('/me', [UserController::class, 'me']);
    Route::get('/dashboard', [UserController::class, 'all_users']);
    Route::get('/logout', [UserController::class, 'logout']);
});



//Route::post('/refresh', [AuthController::class, 'refresh'])->middleware('jwt.verify');



