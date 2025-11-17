<?php

namespace App\Http\Middleware;

use Closure;
use Exception;
use Illuminate\Support\Facades\Auth;

class MobileJwtMiddleware
{
    public function handle($request, Closure $next, $guard = null)
    {
        try {
            // 1. Gunakan guard (default api_user)
            $guard = $guard ?: 'api_user';
            Auth::shouldUse($guard);

            // 2. Ambil token hanya dari Bearer Token
            $token = $request->bearerToken();

            if (!$token) {
                return response()->json([
                    'success' => false,
                    'message' => 'Token tidak ditemukan (gunakan Bearer Token).'
                ], 401);
            }

            // 3. Validasi token & ambil user
            $user = Auth::guard($guard)->setToken($token)->user();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'Token tidak valid atau expired.'
                ], 401);
            }

            // 4. Inject user ke request untuk controller
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
