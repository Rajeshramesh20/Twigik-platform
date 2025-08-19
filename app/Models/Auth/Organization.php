<?php

namespace App\Models\Auth;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use App\Models\User;

class Organization extends Model
{
    use HasFactory;
    protected $table = 'organizations';

    protected $primaryKey = 'org_id';
    
    protected $fillable = [
        'org_name',
        'db_name',
        'db_user',
        'db_pswd',
        'status',
        'is_deleted'
    ];

    public $timestamps = true;

     public function users()
    {
        return $this->belongsToMany(User::class, 'organization_users', 'user_id', 'org_id');
    }
}
