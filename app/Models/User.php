<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    use Notifiable;
    protected $table = 'users';
    protected $fillable = [
        'name',
        'email',
        'password_hash',
        'fullname',
        'phone',
        'avatar_url',
        'role',
        'password_asli',
        'google_id',
        'client_id',
        'client_secret',
        'session_expires_at',
        'last_active_at',
        'status',
        'phone_verified_at',


    ];

    
    protected $hidden = [
        'password',
    ];

    /**
     * Fungsi wajib #1:
     * Ambil primary key user (biasanya ID)
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Fungsi wajib #2:
     * Tambahan payload custom di token (opsional)
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
}
