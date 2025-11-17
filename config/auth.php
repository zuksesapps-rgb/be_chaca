<?php

return [

    'defaults' => [
        'guard' => 'api_user',
        'passwords' => 'users',
    ],

    'guards' => [
        'api_user' => [
            'driver' => 'jwt',
            'provider' => 'users',
        ],

        'api_admin' => [
            'driver' => 'jwt',
            'provider' => 'admins',
        ],
    ],

    'providers' => [
        'users' => [
            'driver' => 'eloquent',
            'model' => App\Models\User\User::class, // <-- pastikan modelnya benar
        ],

        'admins' => [
            'driver' => 'eloquent',
            'model' => App\Models\Admin\User::class, // <-- pastikan modelnya benar
        ],
    ],

    'passwords' => [
        'users' => [
            'provider' => 'users',
            'table' => 'password_reset_tokens',
            'expire' => 60,
            'throttle' => 60,
        ],
    ],

    'password_timeout' => 10800,

];
