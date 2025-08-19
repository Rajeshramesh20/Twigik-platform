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
        Schema::create('organizations', function (Blueprint $table) {
            $table->id('org_id');
            $table->string('org_name')->nullable();
            $table->string('db_name')->nullable(); 
            $table->string('db_user')->nullable(); 
            $table->string('db_pswd')->nullable();
            $table->boolean('status')->default(true);
            $table->timestamps();
            $table->boolean('is_deleted')->default(false); 
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('organizations');
    }
};
