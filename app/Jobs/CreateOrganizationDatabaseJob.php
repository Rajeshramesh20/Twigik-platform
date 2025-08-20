<?php

namespace App\Jobs;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use App\Models\Auth\Organization;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;


class CreateOrganizationDatabaseJob implements ShouldQueue
{
    use Queueable;

    /**
     * Create a new job instance.
     */
    public function __construct(
        protected Organization $organization
    ) {}
    /**
     * Execute the job.
     */
    public function handle(): void
    {
        $dbName = $this->organization->db_name ?? Str::slug($this->organization->org_name, '_');

        DB::statement("CREATE DATABASE IF NOT EXISTS `$dbName`");
    }
}
