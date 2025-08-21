<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\User;
use App\Models\Auth\Organization;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class UserTenantSeeder extends Seeder
{
    public function run(): void
    {
        // Always pull from MAIN DB, not tenant
        $user = User::on('mysql')->latest()->first();
        $organization = Organization::on('mysql')->latest()->first();

        if (!$user || !$organization) {
            return;
        }

        // Insert into tenant's company_users
        $companyUserId = DB::connection('tenant')->table('company_users')->insertGetId([
            'company_user_id' => $user->user_id,
            'name'            => $user->name,
            'org_id'          => $organization->org_id,
            'created_at'      => now(),
            'updated_at'      => now()
        ]);

        // Insert role
        $roleId = DB::connection('tenant')->table('roles')->insertGetId([
            'name'       => 'Super Admin',
            'created_at' => now(),
            'updated_at' => now()
        ]);


        // for ($i = 0; $i < 10; $i++) {
        //     DB::connection('tenant')->table('templates')->insert([
        //         'name'       => 'Template_' . Str::random(8),
        //         'created_at' => now(),
        //         'updated_at' => now(),
        //     ]);
            
        // }

        // Assign role
        DB::connection('tenant')->table('user_role')->insert([
            'user_id'    => $companyUserId,
            'role_id'    => $roleId,
            'created_at' => now(),
            'updated_at' => now()
        ]);
    }
}
?>