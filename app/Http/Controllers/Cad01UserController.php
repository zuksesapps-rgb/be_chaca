<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;
use Symfony\Component\HttpFoundation\Response;

class UserController extends Controller
{
    /**
     * Register user baru
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name'     => 'required|string|max:255',
            'email'    => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors'  => $validator->errors(),
            ], 422);
        }

        $user = User::create([
            'name'     => $request->name,
            'email'    => $request->email,
            'password' => Hash::make($request->password),
        ]);

        return response()->json([
            'success' => true,
            'message' => 'User registered successfully',
            'user'    => $user,
        ], 201);
    }


    /**
     * Login (web & mobile sama saja, bedanya mobile tidak pakai cookie)
     */
    public function login(Request $request)
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

        if (!$token = auth('api')->attempt($request->only('email', 'password'))) {
            return response()->json([
                'success' => false,
                'message' => 'Email atau password salah',
            ], 401);
        }

        $expires_in = auth('api')->factory()->getTTL() * 60;

        // Jika request dari mobile → return JSON token saja
        if ($request->header('User-Agent') == 'mobile') {
            return $this->respondWithToken($token);
        }

        // Kalau web → simpan token dalam cookie httpOnly
        return response()->json([
            'success' => true,
            'message' => 'Login berhasil',
            'user'    => auth('api')->user(),
        ])->cookie('jwt', $token, $expires_in / 60, '/', null, true, true);
    }


    private function respondWithToken($token)
    {
        return response()->json([
            'success'      => true,
            'message'      => 'Login berhasil',
            'user'         => auth('api')->user(),
            'access_token' => $token,
            'token_type'   => 'Bearer',
            'expires_in'   => auth('api')->factory()->getTTL() * 60,
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

        if (!$token = auth('api')->attempt($credentials)) {
            return response()->json([
                'success' => false,
                'message' => 'Email atau password salah',
            ], 401);
        }

        return response()->json([
            'success'      => true,
            'message'      => 'Login berhasil (mobile)',
            'user'         => auth('api')->user(),
            'access_token' => $token,
            'token_type'   => 'Bearer',
            'expires_in'   => auth('api')->factory()->getTTL() * 60,
        ]);
    }


    /**
     * Ambil user yang sedang login
     */
    public function me()
    {
        return response()->json(auth('api')->user());
    }


    /**
     * Update user
     */
    public function update(Request $request)
    {
        $user = auth('api')->user();

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
            // Cek token bearer (untuk mobile)
            $token = $request->bearerToken();

            if ($token) {
                JWTAuth::setToken($token)->invalidate();
            }

            // Hapus cookie HttpOnly (untuk web)
            return response()->json([
                'success' => true,
                'message' => 'Logout berhasil',
            ])->cookie('jwt', '', -1, '/', null, true, true);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Token invalid atau sudah logout',
            ], 401);
        }
    }



    /**
     * Refresh token
     */
    public function refresh()
    {
        return $this->respondWithToken(auth('api')->refresh());
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
