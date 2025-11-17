<?php

namespace App\Http\Controllers\User;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Models\User\User;
use Laravel\Socialite\Facades\Socialite;
use Exception;

class GoogleController extends Controller
{
    /**
     * Redirect ke Google
     */
    public function redirect()
    {
        return Socialite::driver('google')->stateless()->redirect();
    }

    /**
     * Callback dari Google
     */
    public function callback(Request $request)
    {
        try {
            $googleUser = Socialite::driver('google')->stateless()->user();

            // ✅ Cari user berdasarkan email
            $user = User::where('email', $googleUser->getEmail())->first();

            if (!$user) {
                // ✅ Buat user baru
                $user = User::create([
                    'name'       => $googleUser->getName(),
                    'email'      => $googleUser->getEmail(),
                    'google_id'  => $googleUser->getId(),
                    'avatar_url'     => $googleUser->getAvatar(),
                    'password'   => Hash::make(uniqid()), // password random
                    'password_asli' => null, // kamu pakai ini di register
                    'is_verified'   => true,
                ]);
            } else {
                // ✅ Sync google info jika user sudah ada
                $user->update([
                    'google_id' => $googleUser->getId(),
                    'avatar_url'    => $googleUser->getAvatar(),
                ]);
            }

            // ✅ Generate token pakai guard api_user (bukan default)
            $token = auth('api_user')->login($user);

            // ✅ Perhitungan TTL token seperti login
            $expires_in = auth('api_user')->factory()->getTTL() * 60;

            // ✅ Update aktivitas session seperti login biasa
            $user->update([
                'last_active_at'     => now(),
                'session_expires_at' => now()->addDays(30),
            ]);

            // ✅ Kalau request dari Mobile → return JSON
            if ($request->header('User-Agent') === 'mobile') {
                return response()->json([
                    'success' => true,
                    'message' => 'Login Google berhasil.',
                    'data' => [
                        'user'         => $user,
                        'access_token' => $token,
                        'token_type'   => 'bearer',
                        'expires_in'   => $expires_in,
                    ]
                ], 200);
            }

            // ✅ Untuk Web → simpan token di HttpOnly Cookie (seperti login biasa)
            return redirect(env('FRONTEND_URL', 'http://localhost:3000') . '/user/dashboard')
                ->cookie(
                    'jwt_user',    // SAMAKAN DENGAN LOGIN BIASA
                    $token,
                    $expires_in / 60,
                    '/',
                    null,
                    true,   // secure (HTTPS di production)
                    true,   // HttpOnly
                );

        } catch (Exception $e) {
            return redirect(env('FRONTEND_URL', 'http://localhost:3000') . '/user/auth/login?error=google');
        }
    }
}
