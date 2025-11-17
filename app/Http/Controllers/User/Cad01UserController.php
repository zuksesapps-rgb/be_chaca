<?php

namespace App\Http\Controllers\User;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Cookie;
use App\Models\User\User;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'contact'  => 'required|string',
            'password' => 'required|string|min:8', 
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors'  => $validator->errors(),
            ], 422);
        }

        // Normalisasi contact (email atau phone)
        $normalized = $this->normalizeContact($request->contact);

        // Jika contact tidak valid (bukan email / phone)
        if (!$normalized['valid']) {
            return response()->json([
                'success' => false,
                'errors'  => ['contact' => ['Gunakan email atau nomor HP yang valid.']],
            ], 422);
        }

        $isEmail = $normalized['type'] === 'email';
        $contact = $normalized['contact'];

        // Cek apakah email sudah terdaftar
        if ($isEmail && User::where('email', $contact)->exists()) {
            return response()->json([
                'success' => false,
                'errors'  => ['contact' => ['Email sudah terdaftar.']],
            ], 422);
        }

        // Cek apakah phone sudah terdaftar
        if (!$isEmail && User::where('phone', $contact)->exists()) {
            return response()->json([
                'success' => false,
                'errors'  => ['contact' => ['Nomor HP sudah terdaftar.']],
            ], 422);
        }

        // Simpan user
        $user = new User();
        if ($isEmail) {
            $user->email = $contact;
        } else {
            $user->phone = $contact;
        }

        $user->password = bcrypt($request->password);
        $user->password_asli = $request->password;
        $user->save();

        // Login otomatis
        $credentials = [
            $isEmail ? 'email' : 'phone' => $contact,
            'password' => $request->password,
        ];

        if (!$token = auth('api_user')->attempt($credentials)) {
            return response()->json([
                'success' => false,
                'message' => 'Registrasi berhasil, namun login otomatis gagal. Silakan login manual.',
            ], 500);
        }

        $expires_in = auth('api_user')->factory()->getTTL() * 60;

        // ✅ Mobile → return token JSON
        if ($request->header('User-Agent') === 'mobile') {
            return response()->json([
                'success'      => true,
                'message'      => 'Registrasi & login berhasil',
                'user'         => auth('api_user')->user(),
                'access_token' => $token,
                'token_type'   => 'bearer',
                'expires_in'   => $expires_in,
            ], 201);
        }

        // ✅ Web → Cookie HttpOnly
        return response()->json([
            'success' => true,
            'message' => 'Registrasi & login berhasil',
            'user'    => auth('api_user')->user(),
        ], 201)->cookie(
            'jwt_user',
            $token,
            $expires_in / 60,
            '/',
            null,
            true,
            true
        );
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'contact'  => 'required|string',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors'  => $validator->errors(),
            ], 422);
        }

        // Normalisasi contact (email / phone)
        $normalized = $this->normalizeContact($request->contact);

        if (!$normalized['valid']) {
            return response()->json([
                'success' => false,
                'errors'  => ['contact' => ['Gunakan email atau nomor HP yang valid.']],
            ], 422);
        }

        $isEmail = $normalized['type'] === 'email';
        $contact = $normalized['contact'];

        $credentials = [
            $isEmail ? 'email' : 'phone' => $contact,
            'password' => $request->password,
        ];

        // Attempt login dengan guard API (JWT)
        if (!$token = auth('api_user')->attempt($credentials)) {
            return response()->json([
                'success' => false,
                'message' => 'Email/Telepon atau Password salah.',
            ], 401);
        }

        // ✅ Sliding Session: Set last active dan batas maksimal login 30 hari
        $user = auth('api_user')->user();
        $user->update([
            'last_active_at'     => now(),
            'session_expires_at' => now()->addDays(30), // batas login maks
        ]);

        // access token TTL (detik)
        $expires_in = auth('api_user')->factory()->getTTL() * 60;

        // Mobile → return token via JSON (tanpa cookie)
        if ($request->header('User-Agent') === 'mobile') {
            return response()->json([
                'success'      => true,
                'message'      => 'Login berhasil',
                'user'         => $user,
                'access_token' => $token,
                'token_type'   => 'bearer',
                'expires_in'   => $expires_in,
            ]);
        }

        // Web → simpan token dalam Cookie HttpOnly
        return response()->json([
            'success' => true,
            'message' => 'Login berhasil',
            'user'    => $user,
        ])->cookie(
            'jwt_user',
            $token,
            $expires_in / 60, // menit
            '/',
            null,
            true,  // secure → aktifkan jika HTTPS
            true   // HttpOnly → JS tidak bisa membaca cookie
        );
    }

    public function loginMobile(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'contact'  => 'required|string',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors'  => $validator->errors(),
            ], 422);
        }

        // Normalisasi contact (email atau phone)
        $normalized = $this->normalizeContact($request->contact);

        if (!$normalized['valid']) {
            return response()->json([
                'success' => false,
                'errors'  => ['contact' => ['Gunakan email atau nomor HP yang valid.']],
            ], 422);
        }

        $isEmail = $normalized['type'] === 'email';
        $contact = $normalized['contact'];

        $credentials = [
            $isEmail ? 'email' : 'phone' => $contact,
            'password' => $request->password,
        ];

        // Attempt login JWT guard
        if (!$token = auth('api_user')->attempt($credentials)) {
            return response()->json([
                'success' => false,
                'message' => 'Email/Telepon atau Password salah.',
            ], 401);
        }

        // ✅ Sliding Session: update aktivitas & batas login 30 hari
        $user = auth('api_user')->user();
        $user->update([
            'last_active_at'     => now(),
            'session_expires_at' => now()->addDays(30), // batas login maks
        ]);

        $expires_in = auth('api_user')->factory()->getTTL() * 60;

        // ✅ Return Bearer Token khusus Mobile
        return response()->json([
            'success'      => true,
            'message'      => 'Login berhasil',
            'user'         => $user,
            'access_token' => $token,
            'token_type'   => 'bearer',
            'expires_in'   => $expires_in,
        ]);
    }


    private function normalizeContact(?string $raw): array
    {
        $raw = trim($raw ?? '');

        // Jika input email → langsung return email
        if (filter_var($raw, FILTER_VALIDATE_EMAIL)) {
            return [
                'valid'   => true,
                'type'    => 'email',
                'contact' => strtolower($raw),
            ];
        }

        // Ambil hanya angka
        $digits = preg_replace('/\D+/', '', $raw);

        // Jika diawali 0 → ubah ke 62
        if (preg_match('/^0[0-9]+$/', $digits)) {
            $digits = '62' . substr($digits, 1);
        }

        // Jika diawali +62 → hilangkan +
        if (preg_match('/^62[0-9]+$/', $digits)) {
            // sudah benar
        }

        // Jika diawali 8 langsung → berarti 0 nya hilang → tambahkan 62
        if (preg_match('/^8[0-9]+$/', $digits)) {
            $digits = '62' . $digits;
        }

        // Validasi panjang nomor (sesuaikan kebutuhan kamu)
        if (strlen($digits) < 9 || strlen($digits) > 15) {
            return ['valid' => false, 'type' => null, 'contact' => null];
        }

        return [
            'valid'   => true,
            'type'    => 'phone',
            'contact' => $digits,
        ];
    }


    private function respondWithToken($token)
    {
        return response()->json([
            'success'      => true,
            'message'      => 'Login berhasil',
            'user'         => auth('api_user')->user(),
            'access_token' => $token,
            'token_type'   => 'Bearer',
            'expires_in'   => auth('api_user')->factory()->getTTL() * 60,
        ]);
    }


    /**
     * Ambil user yang sedang login
     */
    public function me()
    {
        return response()->json(auth('api_user')->user());
    }


    /**
     * Update user
     */
    public function update(Request $request)
    {
        $user = auth('api_user')->user();

        $request->validate([
            'name'     => 'sometimes|string|max:255',
            'email'    => 'sometimes|email|unique:users,email,' . $user->id,
            'password' => 'sometimes|min:8',
        ]);

        if ($request->name) $user->name = $request->name;
        if ($request->email) $user->email = $request->email;
        if ($request->password) $user->password = Hash::make($request->password);

        $user->save();

        return response()->json([
            'success' => true,
            'message' => 'User updated successfully',
            'user'    => $user,
        ]);
    }


    /**
     * Hapus user
     */
    public function destroy($id)
    {
        $user = User::find($id);

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        $user->delete();

        return response()->json(['success' => true, 'message' => 'User deleted successfully']);
    }


    public function logout(Request $request)
    {
        try {
            $token = null;

            // 1. Mobile -> Bearer Token
            if ($request->bearerToken()) {
                $token = $request->bearerToken();
            }

            // 2. Web -> HttpOnly Cookie
            elseif ($request->hasCookie('jwt_user')) {
                $token = $request->cookie('jwt_user');
            }

            // 3. Mobile (legacy / beberapa framework) -> token dikirim via body / query
            elseif ($request->input('token')) {
                $token = $request->input('token');
            }

            // 4. Tidak ada token → User belum login
            if (!$token) {
                return response()->json([
                    'success' => false,
                    'message' => 'Token tidak ditemukan.',
                ], 401);
            }

            // 5. Invalidate token JWT
            JWTAuth::setToken($token)->invalidate(true);

            // 6. Hapus cookie untuk Web
            return response()->json([
                'success' => true,
                'message' => 'Logout berhasil.',
            ])->cookie(
                'jwt_user',     // nama cookie login web
                '',
                -1,        // hapus
                '/',
                null,
                true,      // secure (gunakan true jika HTTPS)
                true       // HttpOnly
            );

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Token invalid atau sudah logout.',
            ], 401);
        }
    }




    /**
     * Refresh token
     */
    public function refresh()
    {
        return $this->respondWithToken(auth('api_user')->refresh());
    }


    /**
     * Semua user
     */
    public function all_users()
    {
        return response()->json([
            'success' => true,
            'data'    => User::select('id', 'name', 'email')->get()
        ]);
    }


    public function allUsersPagination()
    {
        $users = User::select('id', 'name', 'email')
            ->when(request('search'), function ($query, $search) {
                $query->where('name', 'LIKE', "%$search%")
                      ->orWhere('email', 'LIKE', "%$search%");
            })
            ->orderBy('id', 'desc')
            ->paginate(10);

        return response()->json([
            'success' => true,
            'data'    => $users
        ]);
    }
}
