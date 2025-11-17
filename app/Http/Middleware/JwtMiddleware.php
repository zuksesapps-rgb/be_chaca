<?php

namespace App\Http\Middleware;

use Closure;
use Exception;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Facades\JWTAuth;

class JwtMiddleware
{
    public function handle($request, Closure $next, $guard = null)
    {
        try {
            // Tentukan guard berdasarkan route
            $guard = $guard ?: 'api_user';
            Auth::shouldUse($guard);

            // Ambil token dari cookie sesuai guard
            $cookieName = $guard === 'api_admin' ? 'jwt_admin' : 'jwt_user';

            if (!$request->hasCookie($cookieName)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Token tidak ditemukan (cookie tidak ada).'
                ], 401);
            }

            $token = $request->cookie($cookieName);

            if (!$token) {
                return response()->json([
                    'success' => false,
                    'message' => 'Token tidak valid (kosong).'
                ], 401);
            }

            // Validasi & ambil user
            $user = Auth::guard($guard)->setToken($token)->user();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'Token tidak valid.'
                ], 401);
            }

            // inject user ke request()
            $request->setUserResolver(fn () => $user);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Token invalid atau expired.'
            ], 401);
        }

        return $next($request);
    }
}
