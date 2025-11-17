<?php

namespace App\Http\Middleware;

use Closure;
use Exception;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;

class WebJwtMiddleware
{
    public function handle($request, Closure $next, $guard = 'api_user')
    {
        
        // 🚀 Izinkan refresh token walaupun expired
        if ($request->is('user/auth/refresh')) {
            return $next($request);
        }

        // Gunakan guard sesuai kebutuhan (api_user / api_admin)
        Auth::shouldUse($guard);

        $cookieName = $guard === 'api_admin' ? 'jwt_admin' : 'jwt_user';

        // Token harus ada di cookie
        if (!$request->hasCookie($cookieName)) {
            return response()->json([
                'success' => false,
                'message' => 'Token tidak ditemukan (cookie kosong).'
            ], 401);
        }

        $token = $request->cookie($cookieName);

        try {
            // Jika token valid → ambil user
            $user = Auth::guard($guard)->setToken($token)->user();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'User tidak ditemukan.'
                ], 401);
            }

            // Inject user ke request()
            $request->setUserResolver(fn () => $user);

        } catch (TokenExpiredException $e) {
            // Token expired → Biarkan Next.js mencoba refresh
            return response()->json([
                'success' => false,
                'message' => 'TOKEN_EXPIRED'
            ], 401);
        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Token invalid.',
                'error'   => $e->getMessage()
            ], 401);
        }

        return $next($request);
    }
}
