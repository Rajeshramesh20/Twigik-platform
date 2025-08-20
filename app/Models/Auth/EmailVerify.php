<?php

namespace App\Models\Auth;

use Illuminate\Database\Eloquent\Model;

class EmailVerify extends Model
{
    protected $table = 'email_templates';

    protected $fillable = ['key', 'subject', 'body'];

    
    public static function findBy($column, $value)
    {
        return static::where($column, $value)->first();
    }
}
