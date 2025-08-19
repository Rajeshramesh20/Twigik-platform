<?php

namespace App\Models\Auth;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

/**
 * @mixin IdeHelperOrganizationUser
 */
class OrganizationUser extends Model
{
    use HasFactory;
    protected $table = 'organization_users';

    protected $primaryKey = 'org_user_id';

    protected $fillable = [
        'org_id',
        'user_id',
        'status',
        'is_deleted'
    ];

    public $timestamps = true;
}
