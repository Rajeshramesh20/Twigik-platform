<?php

namespace App\Models\Auth;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use App\Models\User;

/**
 * @mixin IdeHelperAuthToken
 */
class AuthToken extends Model
{
    use HasFactory;
    protected $table = 'auth_tokens';

    protected $fillable = [
        'user_id',
        'token',
        'expires_at',
        'revoked_at'
    ];
    
    protected $dates = ['expires_at', 'revoked_at'];

    public $timestamps = true;


    public function user(){
        return $this->belongsTo(User::class , 'user_id');
    }
}
