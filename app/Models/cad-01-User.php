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
        'password',
        'role',
        'status',
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
