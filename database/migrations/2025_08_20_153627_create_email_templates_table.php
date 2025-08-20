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
        Schema::create('email_templates', function (Blueprint $table) {
            $table->id();
            $table->string('key')->unique();
            $table->string('subject');
            $table->longText('body');
            $table->timestamps();
        });


        // Insert default templates
        DB::table('email_templates')->insert([
            [
                'key'     => 'verify_email',
                'subject' => 'Verify Your Email',
                'body'    => "
                    Hi {{name}},<br><br>
                    Please verify your email by clicking the link below:<br>
                    <a href='{{verification_link}}'>Verify Email</a><br><br>
                    This link will expire in 30 minutes.<br><br>
                ",
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'key'     => 'password_reset',
                'subject' => 'Reset Your Password',
                'body'    => "
                    Hi {{name}},<br><br>
                    You requested to reset your password. Click the link below to reset it:<br>
                    <a href='{{reset_link}}'>Reset Password</a><br><br>
                    This link will expire in 30 minutes.<br><br>
                    If you did not request a password reset, please ignore this email.<br><br>
                    Regards,<br>Your App Team
                ",
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ]);
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('email_templates');
    }
};
