<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('organization_users', function (Blueprint $table) {
            $table->id('org_user_id');
              $table->unsignedBigInteger('org_id'); // FK to organizations
            $table->unsignedBigInteger('user_id'); // FK to users
            $table->timestamps();
            $table->boolean('status')->default(1); 
            $table->boolean('is_deleted')->default(0);


            $table->foreign('org_id')->references('org_id')->on('organizations')->onDelete('cascade');
            $table->foreign('user_id')->references('user_id')->on('users')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('organization_users');
    }
};
