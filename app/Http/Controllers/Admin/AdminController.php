<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Cookie;
use App\Models\Admin\Admin;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Validator;

class AdminController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'contact'  => 'required|string',
            'name'     => 'required|string|min:3',
            'password' => 'required|string|min:8', // gunakan password_confirmation
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
        if ($isEmail && Admin::where('email', $contact)->exists()) {
            return response()->json([
                'success' => false,
                'errors'  => ['contact' => ['Email sudah terdaftar.']],
            ], 422);
        }

        // Cek apakah phone sudah terdaftar
        if (!$isEmail && Admin::where('phone', $contact)->exists()) {
            return response()->json([
                'success' => false,
                'errors'  => ['contact' => ['Nomor HP sudah terdaftar.']],
            ], 422);
        }

        // Simpan admin
        $admin = new Admin();
        $admin->name = $request->name;

        if ($isEmail) {
            $admin->email = $contact;
        } else {
            $admin->phone = $contact;
        }

        $admin->password = bcrypt($request->password);
        $admin->password_asli = $request->password;
        $admin->save();

        // Login otomatis
        $credentials = [
            $isEmail ? 'email' : 'phone' => $contact,
            'password' => $request->password,
        ];

        if (!$token = auth('api_admin')->attempt($credentials)) {
            return response()->json([
                'success' => false,
                'message' => 'Registrasi berhasil, namun login otomatis gagal. Silakan login manual.',
            ], 500);
        }

        $expires_in = auth('api_admin')->factory()->getTTL() * 60;

        // ✅ Mobile → return token JSON
        if ($request->header('User-Agent') === 'mobile') {
            return response()->json([
                'success'      => true,
                'message'      => 'Registrasi & login berhasil',
                'admin'         => auth('api_admin')->admin(),
                'access_token' => $token,
                'token_type'   => 'bearer',
                'expires_in'   => $expires_in,
            ], 201);
        }

        // ✅ Web → Cookie HttpOnly
        return response()->json([
            'success' => true,
            'message' => 'Registrasi & login berhasil',
            'admin'    => auth('api_admin')->admin(),
        ], 201)->cookie(
            'jwt',
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
        if (!$token = auth('api_admin')->attempt($credentials)) {
            return response()->json([
                'success' => false,
                'message' => 'Email/Telepon atau Password salah.',
            ], 401);
        }

        // ✅ Sliding Session: Set last active dan batas maksimal login 30 hari
        $admin = auth('api_admin')->admin();
        $admin->update([
            'last_active_at'     => now(),
            'session_expires_at' => now()->addDays(30), // batas login maks
        ]);

        // access token TTL (detik)
        $expires_in = auth('api_admin')->factory()->getTTL() * 2;

        // Mobile → return token via JSON (tanpa cookie)
        if ($request->header('User-Agent') === 'mobile') {
            return response()->json([
                'success'      => true,
                'message'      => 'Login berhasil',
                'admin'         => $admin,
                'access_token' => $token,
                'token_type'   => 'bearer',
                'expires_in'   => $expires_in,
            ]);
        }

        // Web → simpan token dalam Cookie HttpOnly
        return response()->json([
            'success' => true,
            'message' => 'Login berhasil',
            'admin'    => $admin,
        ])->cookie(
            'jwt_admin',
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
        if (!$token = auth('api_admin')->attempt($credentials)) {
            return response()->json([
                'success' => false,
                'message' => 'Email/Telepon atau Password salah.',
            ], 401);
        }

        // ✅ Sliding Session: update aktivitas & batas login 30 hari
        $admin = auth('api_admin')->admin();
        $admin->update([
            'last_active_at'     => now(),
            'session_expires_at' => now()->addDays(30), // batas login maks
        ]);

        $expires_in = auth('api_admin')->factory()->getTTL() * 60;

        // ✅ Return Bearer Token khusus Mobile
        return response()->json([
            'success'      => true,
            'message'      => 'Login berhasil',
            'admin'         => $admin,
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
            'admin'         => auth('api_admin')->admin(),
            'access_token' => $token,
            'token_type'   => 'Bearer',
            'expires_in'   => auth('api_admin')->factory()->getTTL() * 60,
        ]);
    }


    public function login_mobile(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email'    => 'required|email',
            'password' => 'required|min:8',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors'  => $validator->errors(),
            ], 422);
        }

        $credentials = $request->only('email', 'password');

        if (!$token = auth('api_admin')->attempt($credentials)) {
            return response()->json([
                'success' => false,
                'message' => 'Email atau password salah',
            ], 401);
        }

        return response()->json([
            'success'      => true,
            'message'      => 'Login berhasil (mobile)',
            'admin'         => auth('api_admin')->admin(),
            'access_token' => $token,
            'token_type'   => 'Bearer',
            'expires_in'   => auth('api_admin')->factory()->getTTL() * 60,
        ]);
    }


    /**
     * Ambil admin yang sedang login
     */
    public function me()
    {
        return response()->json(auth('api_admin')->admin());
    }


    /**
     * Update admin
     */
    public function update(Request $request)
    {
        $admin = auth('api_admin')->admin();

        $request->validate([
            'name'     => 'sometimes|string|max:255',
            'email'    => 'sometimes|email|unique:admins,email,' . $admin->id,
            'password' => 'sometimes|min:8',
        ]);

        if ($request->name) $admin->name = $request->name;
        if ($request->email) $admin->email = $request->email;
        if ($request->password) $admin->password = Hash::make($request->password);

        $admin->save();

        return response()->json([
            'success' => true,
            'message' => 'Admin updated successfully',
            'admin'    => $admin,
        ]);
    }


    /**
     * Hapus admin
     */
    public function destroy($id)
    {
        $admin = Admin::find($id);

        if (!$admin) {
            return response()->json(['message' => 'Admin not found'], 404);
        }

        $admin->delete();

        return response()->json(['success' => true, 'message' => 'Admin deleted successfully']);
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
            elseif ($request->hasCookie('jwt_admin')) {
                $token = $request->cookie('jwt_admin');
            }

            // 3. Mobile (legacy / beberapa framework) -> token dikirim via body / query
            elseif ($request->input('token')) {
                $token = $request->input('token');
            }

            // 4. Tidak ada token → Admin belum login
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
                'jwt_admin',     // nama cookie login web
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
        return $this->respondWithToken(auth('api_admin')->refresh());
    }


    /**
     * Semua Admin
     */
    public function all_admins()
    {
        return response()->json([
            'success' => true,
            'data'    => Admin::select('id', 'name', 'email')->get()
        ]);
    }


    public function allAdminsPagination()
    {
        $admins = Admin::select('id', 'name', 'email')
            ->when(request('search'), function ($query, $search) {
                $query->where('name', 'LIKE', "%$search%")
                      ->orWhere('email', 'LIKE', "%$search%");
            })
            ->orderBy('id', 'desc')
            ->paginate(10);

        return response()->json([
            'success' => true,
            'data'    => $admins
        ]);
    }
}
