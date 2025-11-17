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
        $User = new User();
        if ($isEmail) {
            $User->email = $contact;
        } else {
            $User->phone = $contact;
        }

        $User->password = bcrypt($request->password);
        $User->password_asli = $request->password;
        $User->save();

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
            true,
            'Strict'
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
                'code'    => 'VALIDATION_ERROR',
                'message' => 'Periksa kembali input anda.',
                'errors'  => $validator->errors(),
                'already_registered' => null
            ], 422);
        }

        // Normalisasi contact (email / phone)
        $normalized = $this->normalizeContact($request->contact);

        if (!$normalized['valid']) {
            return response()->json([
                'success' => false,
                'code'    => 'INVALID_CONTACT_FORMAT',
                'message' => 'Gunakan email atau nomor HP yang valid.',
                'already_registered' => null
            ], 422);
        }

        $isEmail = $normalized['type'] === 'email';
        $contact = $normalized['contact'];

        // Cek apakah user terdaftar
        $user = User::where($isEmail ? 'email' : 'phone', $contact)->first();
        if (!$user) {
            return response()->json([
                'success' => false,
                'code'    => 'USER_NOT_FOUND',
                'message' => 'Akun belum terdaftar.',
                'already_registered' => false,
                'data' => [
                    'contact'  => $contact,
                    'is_email' => $isEmail,
                ]
            ], 404);
        }

        $credentials = [
            $isEmail ? 'email' : 'phone' => $contact,
            'password' => $request->password,
        ];

        // Attempt login
        if (!$token = auth('api_user')->attempt($credentials)) {
            return response()->json([
                'success' => false,
                'code'    => 'INVALID_CREDENTIALS',
                'message' => 'Password salah.',
                'already_registered' => true
            ], 401);
        }

        // Update aktivitas session
        $user = auth('api_user')->user();
        $user->update([
            'last_active_at'     => now(),
            'session_expires_at' => now()->addDays(30),
        ]);

        // access token TTL (detik)
        //$expires_in = auth('api_user')->factory()->getTTL() * 1;
        $ttl = auth('api_user')->factory()->getTTL(); // menit
        $expires_in = $ttl * 60; // detik

        // Mobile → return token langsung
        if ($request->header('User-Agent') === 'mobile') {
            return response()->json([
                'success' => true,
                'code'    => 'LOGIN_SUCCESS',
                'message' => 'Login berhasil.',
                'already_registered' => true,
                'data' => [
                    'user'         => $user,
                    'access_token' => $token,
                    'token_type'   => 'bearer',
                    'expires_in'   => $expires_in,
                ]
            ], 200);
        }

        // Web → simpan token dalam cookie
        return response()->json([
            'success' => true,
            'code'    => 'LOGIN_SUCCESS',
            'message' => 'Login berhasil.',
            'already_registered' => true,
            'data' => [
                'user' => $user,
            ]
        ])->cookie(
            'jwt_user',
            $token,
            $expires_in / 60,
            '/',
            null,
            false,   // secure=false untuk localhost
            true,    // httpOnly=true
            false,
            'Strict'    // SameSite Lax cocok untuk localhost
            //'Strict'
        );
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



    public function sendOtp(Request $request)
    {
        $request->validate([
            'contact' => 'required|string',
        ]);

        // 🔧 Normalisasi kontak (email atau phone)
        $normalized = $this->normalizeContact($request->contact);
        $type = $normalized['type'];
        $contact = $normalized['contact'];

        // 🔢 Buat OTP acak 6 digit
        $otp = rand(100000, 999999);

        // 💾 Simpan OTP ke cache selama 50 menit
        $cacheKey = $type === 'email' ? "otp_email_{$contact}" : "otp_{$contact}";
        Cache::put($cacheKey, $otp, now()->addMinutes(50));

        Log::info('OTP generated', ['key' => $cacheKey, 'otp' => $otp]);

        try {
            if ($type === 'email') {
                Mail::raw(
                    "Kode OTP Anda adalah: {$otp}. Berlaku selama 50 menit.",
                    function ($message) use ($contact) {
                        $message->to($contact)->subject('Kode OTP Login Anda');
                    }
                );
            } else {
                Http::withHeaders([
                    'Authorization' => env('FONNTE_TOKEN'),
                ])->asForm()->post('https://api.fonnte.com/send', [
                    'target' => $contact,
                    'message' => "🔐 Kode OTP Anda adalah *{$otp}*. Berlaku selama 50 menit.",
                ]);
            }
        } catch (\Throwable $e) {
            Log::error('Gagal mengirim OTP', ['error' => $e->getMessage()]);
            return response()->json([
                'success' => false,
                'message' => 'Gagal mengirim OTP. Silakan coba lagi.',
            ], 500);
        }

        return response()->json([
            'success' => true,
            'message' => "Kode OTP telah dikirim ke {$type}: {$contact}",
            'otp' => app()->environment('local') ? $otp : null, // tampilkan OTP hanya di local
        ]);
    }

    public function verifyOtp(Request $request)
    {
        $request->validate([
            'contact' => 'required|string',
            'otp' => 'required|string|size:6',
        ]);

        $normalized = $this->normalizeContact($request->contact);
        $isEmail = $normalized['type'] === 'email';
        $contact = $normalized['contact'];
        $otp = trim($request->otp);

        $cacheKey = $isEmail ? "otp_email_{$contact}" : "otp_{$contact}";
        $cachedOtp = Cache::get($cacheKey);

        Log::info('Verifying OTP', ['key' => $cacheKey, 'cached' => $cachedOtp, 'input' => $otp]);

        if (!$cachedOtp) {
            return response()->json([
                'success' => false,
                'message' => 'Kode OTP sudah kadaluarsa. Silakan minta ulang.',
            ], 400);
        }

        if ((string) $cachedOtp !== (string) $otp) {
            return response()->json([
                'success' => false,
                'message' => 'Kode OTP salah.',
            ], 400);
        }

        // 🔍 Cek apakah user sudah ada
        $existingUser = $isEmail
            ? User::where('email', $contact)->first()
            : User::where('phone', $contact)->first();

        if ($existingUser) {
            $existingUser->is_verified = true;
            $existingUser->save();

            return response()->json([
                'success' => true,
                'already_registered' => true,
                'message' => 'Akun sudah terdaftar. Silakan login.',
                'user' => $existingUser,
            ]);
        }

        // Jika belum terdaftar → arahkan buat password
        return response()->json([
            'success' => true,
            'already_registered' => false,
            'message' => 'Verifikasi OTP berhasil. Silakan lanjut buat password.',
            'contact' => $contact,
        ]);
    }

    public function createAccount(Request $request)
    {
        $request->validate([
            'contact' => 'required|string',
            'password' => 'required|string|min:6',
        ]);

        $normalized = $this->normalizeContact($request->contact);
        $isEmail = $normalized['type'] === 'email';
        $contact = $normalized['contact'];

        $rawPassword = $request->password;
        $hashedPassword = Hash::make($rawPassword);

        // Cari user
        $user = $isEmail
            ? User::where('email', $contact)->first()
            : User::where('phone', $contact)->first();

        // Kalau user belum ada → buat baru
        if (!$user) {
            $user = User::create([
                $isEmail ? 'email' : 'phone' => $contact,
                'password' => $hashedPassword,
                'is_verified' => true,
            ]);
        } 
        // Kalau user sudah ada → update password & tanda verifikasi
        else {
            // $user->password = $hashedPassword;
            // $user->is_verified = true;
            // $user->save();
        }

        // access token TTL (detik)
        $expires_in = auth('api_user')->factory()->getTTL() * 60;

        // Login otomatis
        $credentials = [
            $isEmail ? 'email' : 'phone' => $contact,
            'password' => $rawPassword,
        ];

        if (!$token = auth()->attempt($credentials)) {
            return response()->json([
                'success' => false,
                'message' => 'Gagal login setelah membuat password. Silakan login manual.',
            ], 500);
        }

        return response()->json([
            'success' => true,
            'code'    => 'LOGIN_SUCCESS',
            'message' => 'Akun berhasil dibuat & login otomatis.',
            'already_registered' => true,
            'data' => [
            'user' => $user,
            ]
        ])->cookie(
            'jwt_user',
            $token,
            $expires_in / 60,
            '/',
            null,
            true,
            true,
            false,
            'Strict'
        );
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
            'full_name' => 'sometimes|string|max:255',
            'email'     => 'sometimes|email|unique:users,email,' . $user->id,
            'username'  => 'sometimes|min:8',
            'password'  => 'sometimes|min:8',
            'phone'     => 'sometimes|string|max:255|unique:users,phone,' . $user->id,
            'foto'     => 'sometimes|image|mimes:jpg,jpeg,png,webp|max:4096',
        ]);

        if ($request->full_name) $user->full_name = $request->full_name;
        if ($request->email)     $user->email     = $request->email;
        if ($request->password)  $user->password  = Hash::make($request->password);
        if ($request->phone)     $user->phone     = $request->phone;

        /**
         * HANDLE GAMBAR
         */
        if ($request->hasFile('foto')) {

            // Hapus gambar lama jika ada
            if ($user->avatar_url) {
                $oldPath = public_path('images/' . basename($user->avatar_url));
                if (file_exists($oldPath)) {
                    unlink($oldPath); // hapus file lama
                }
            }

            // Upload gambar baru
            $filename = time() . '_' . uniqid() . '.' . $request->foto->extension();
            $request->foto->move(public_path('images'), $filename);

            // Simpan url baru
            $user->avatar_url = "https://zukses.com/images/" . $filename;
        }

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

            // 1. Mobile → Bearer Token
            if ($request->bearerToken()) {
                $token = $request->bearerToken();
            }

            // 2. Web → HttpOnly Cookie
            elseif ($request->hasCookie('jwt_user')) {
                $token = $request->cookie('jwt_user');
            }

            // 3. Mobile Legacy → token dari body / query
            elseif ($request->input('token')) {
                $token = $request->input('token');
            }

            // 4. Jika token tetap tidak ada → user belum login
            if (!$token) {
                return response()->json([
                    'success' => false,
                    'message' => 'Token tidak ditemukan.',
                ], 401);
            }

            // 5. Invalidate Token JWT
            JWTAuth::setToken($token)->invalidate(true);

            // 6. Hapus cookie Web (jwt_user)
            $forgetCookie = cookie()->forget(
                'jwt_user',
                '/',     // path
                null,    // domain
                true,    // secure = true (ubah ke false jika masih localhost http)
                true,    // httpOnly
                false,
                'None'    // SameSite (ubah ke None jika SPA berbeda domain)
            );

            return response()->json([
                'success' => true,
                'message' => 'Logout berhasil.',
            ])->withCookie($forgetCookie);

        } catch (\Exception $e) {

            return response()->json([
                'success' => false,
                'message' => 'Token invalid atau sudah logout.',
                'error'   => $e->getMessage(), // opsional
            ], 401);
        }
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

    public function refresh(Request $request)
    {
        try {
            $oldToken = $request->cookie('jwt_user');

            if (!$oldToken) {
                return response()->json(['message' => 'Token tidak ditemukan'], 401);
            }

            // ❗ Gunakan JWTAuth langsung, bukan auth('api_user')
            $newToken = JWTAuth::setToken($oldToken)->refresh();

            // waktu hidup token baru
            $expires_in = config('jwt.ttl') * 60;

            return response()
                ->json([
                    'success' => true,
                    'message' => 'Token diperbarui',
                ])
                ->cookie(
                    'jwt_user',
                    $newToken,
                    $expires_in / 60,
                    '/',
                    null,
                    false,   // secure=false untuk localhost
                    true,    // httpOnly
                    false,
                    //'Strict'    // Lax paling aman untuk SPA localhost
                );

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Refresh gagal',
                'error' => $e->getMessage()
            ], 401);
        }
    }


}
