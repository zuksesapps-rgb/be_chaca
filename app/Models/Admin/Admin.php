<?php

namespace App\Models\Admin;

use Illuminate\Foundation\Auth\Admin as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Tymon\JWTAuth\Contracts\JWTSubject;

class Admin extends Authenticatable implements JWTSubject
{
    use Notifiable;
    protected $table = 'admins';
    protected $fillable = [
        'name',
        'email',
        'password',
        'password_asli',
        'phone',
        'avatar',
        'role',
        'status',
        'google_id',
        'client_id',
        'client_secret',
        'session_expires_at',
        'last_active_at',

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
