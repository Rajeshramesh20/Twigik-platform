<?php

namespace App\Jobs;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use App\Models\Auth\Organization;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Artisan;
use App\Models\User;
use Database\Seeders\TenantSeeder;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Config;
use Exception;

class CreateOrganizationDatabaseJob implements ShouldQueue
{
    use Queueable;

    public function __construct(
        protected Organization $organization,
        protected User $user
    ) {}

    public function handle(): void
    {
        $dbName = $this->organization->db_name ?? Str::slug($this->organization->org_name, '_');

        // 1) Create DB using main connection
        $charset = config('database.connections.mysql.charset', 'utf8mb4');
        $collation = config('database.connections.mysql.collation', 'utf8mb4_unicode_ci');

        DB::connection('mysql')->statement("CREATE DATABASE IF NOT EXISTS `$dbName` CHARACTER SET $charset COLLATE $collation");

        // 2) Configure tenant connection properly
        $tenantConfig = [
            'driver' => 'mysql',
            'host' => config('database.connections.mysql.host'),
            'port' => config('database.connections.mysql.port'),
            'database' => $dbName,
            'username' => config('database.connections.mysql.username'), // Use the same credentials as main DB
            'password' => config('database.connections.mysql.password'),
            'charset' => $charset,
            'collation' => $collation,
            'prefix' => '',
            'prefix_indexes' => true,
            'strict' => true,
            'engine' => null,
        ];

        // Set the configuration
        Config::set('database.connections.tenant', $tenantConfig);

        // 3) Purge and reconnect
        DB::purge('tenant');
        DB::reconnect('tenant');

        // 4) Test connection before migrating
        try {
            DB::connection('tenant')->getPdo();

            // 5) Run migrations
            Artisan::call('migrate', [
                '--database' => 'tenant',
                '--path' => 'database/migrations/tenant',
                '--force' => true,
            ]);

             Log::info("✅ Successfully created and seeded database: $dbName");
        } catch (Exception $e) {

            Log::error("❌ Failed to create tenant database: " . $e->getMessage());
            throw $e;
        }
    }

   
}
