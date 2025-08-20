<?php

namespace App\Services;

use App\Models\User;
use App\Models\Auth\AuthToken;
use App\Models\Auth\Organization;
use App\Models\Auth\OrganizationUser;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;

use App\Http\Resources\Auth\LoginResource;
use App\Http\Resources\Auth\OrgResource;

use App\Jobs\verifyEmail;

use Throwable;

class AuthServices
{
    //user registration
    public function register(array $data)
    {
        try {    
            //create User Table
            $user = User::create([
                'user_uuid'       => $data['user_uuid'] ?? Str::uuid()->toString(),
                'name'            => $data['name'],
                'email'           => $data['email'],
                'password'        => Hash::make($data['password']),
                'is_verified'     => $data['is_verified'] ?? false,
                'is_active'       => $data['is_active'] ?? true,
                'last_login_at'   => null,
                'failed_attempts' => 0,
                'recovery_token'  => null,
                'is_deleted'      => false,
             ]);

            //create Organization Table
            $organization = Organization::create([
                'org_name'   => $data['org_name'], 
                'db_name'    => $data['db_name'] ?? null,
                'db_user'    => $data['db_user'] ?? null,
                'db_pswd'    => $data['db_pswd'] ?? null,
                'status'     => $data['status'] ?? true,
                'is_deleted' => false,
            ]);

            //Create Pivot Table
            OrganizationUser::create([
                'org_id'     => $organization->org_id,
                'user_id'    => $user->user_id,
                'status'     => true,
                'is_deleted' => false,
            ]);


            // Generate Email Verification Token
            $token = Str::random(64);

            AuthToken::create([
                'user_id'    => $user->user_id,
                'token'      => $token,
                'expires_at' => Carbon::now()->addMinutes(30), // token valid for 30 min
                'revoked_at' => null,
            ]);


            $verificationLink = url('/verify-email?token=' . $token);

            verifyEmail::dispatch($data, $verificationLink);

            // Mail::send([], [], function ($message) use ($data, $verificationLink) {
            //     $message->to($data['email'])
            //         ->subject('Verify Your Email')
            //         ->html(
            //             "Hi {$data['name']},<br><br>" .
            //                 "Please verify your email by clicking the link below:<br>" .
            //                 "<a href='{$verificationLink}'>Verify Email</a><br><br>" .
            //                 "This link will expire in 30 minutes.<br><br>" .
            //                 "Regards,<br>Your App Team"
            //         );
            // });

                return $user;

            }catch(Throwable $e) {
                 Log::error('Registration failed', ['error_message' => $e->getMessage()]);
            }
    }

    //email verification
    public function verifyEmail($token)
    {
        try {
            $authToken = AuthToken::where('token', $token)
                ->whereNull('revoked_at')
                ->first();

            // Log::error('auth token' . $authToken);  

            if (!$authToken) {
                return [
                    'status'  => false,
                    'message' => __('auth.invalid_token'),
                    'code'    => 400
                ];
            }

           // Check if token is expiry
            if (Carbon::now()->greaterThan($authToken->expires_at)) {
                return [
                    'status'  => false,
                    'message' => __('auth.expiry_token'),
                    'code'    => 400
                ];
            }

            $user = $authToken->user;
            
            //update the email verify column
            $user->update([
                'is_verified' => true,
                'email_verified_at' => Carbon::now()
            ]);

            //create  user Org name DB 
            $organization = $user->organizations()->first();
            if ($organization) {
                 $organization->update(['status' => true]);

                //Create dynamic DB
                $dbName = $organization->db_name ?? Str::slug($organization->org_name, '_');
                DB::statement("CREATE DATABASE IF NOT EXISTS `$dbName`");
            }
            $authToken->update(['revoked_at' => Carbon::now()]);
            
            return [
                'status'  => true,
                'message' => __('auth.mail_verification'),
                'code'    => 200
            ];

        }catch(Throwable $e){

            Log::error('Error in verify email', ['error_message' => $e->getMessage()]);
        }
    }

    //user login
    public function userLogin($data)
    {

    try {
        $user =  User::where('email', $data['email'])->first();

        // Check if user is found
        if(!$user){
            return [
                'status'  => false,
                'message' => __('auth.login_failed'),
                'code'    => 401
            ];
        }

        // Check if user is locked
        if($user->lockout_time && $user->lockout_time > now()){
            return [
                'status'  => false,
                'message' => __('auth.login_attempts'),
                'code'    => 403
            ];
        }

        //requested Data
        $userData = [
            'email'    => $data['email'],
            'password' => $data['password'],
        ];

        if(!Auth::attempt($userData)){

            $user->increment('failed_attempts');

             //Lock Login in 5 minutes
             if($user->failed_attempts >= 5) {
                $user->update([
                    'lockout_time' => now()->addMinutes(5), // lock 5 mins
                    'failed_attempts' => 0 
            ]);
            return [
                'status'  => false,
                'message' => __('auth.login_attempts'),
                'code'    => 403
            ];
            }
            return [
                'status'  => false,
                'message' =>  __('auth.login_failed'),
                'code'    => 404
            ];
        }

        $user->update([
            'last_login_at'   => Carbon::now(),
            'lockout_time'    => null
        ]);

        $tokenResult = $user->createToken('userToken');
        $token = $tokenResult->accessToken;
        $tokenExpiry = $tokenResult->token->expires_at;

        Log::error('organization' , ['organization' =>  $user->organizations]);
        // Log::info('token expires time', ['token' => $tokenExpiry]);

        return [
            'status'  => true,
            'message' => __('auth.login_success'),
            'data'    =>  new LoginResource(auth()->user()),
            'organization' => OrgResource::collection($user->organizations),
            'token'   => $token,
            'expires_in' => $tokenExpiry->diffInSeconds(now()),
            'code'    => 200
        ];
        }catch(Throwable $e){
            Log::error('Login Failed', ['error_message' => $e->getMessage()]);
        }
    }


    //logout 
    public function userLogout($request)
    {
        try{
            // token is revoke(1)
            $request->user()->token()->revoke();

             return [
                'status'  => true,
                'message' => __('auth.logout'),
                'code'    => 200
            ];
        }catch(Throwable $e){
            Log::error('Error: logout failed', ['error_message' => $e->getMessage()]);
        }    
    }


    //send forgot password link to mail
    public function submitForgotPasswordForm($data)
    {
        try{
            $user = User::where('email', $data['email'])->first();

            // Check if user email is found
            if(!$user){
                return [
                    'status' => 'error',
                    'message' => __('auth.email_error'),
                    'code'    => 404
                ];
            }

            //create random token
            $token = Str::random(64);

            //insert the token&email into (password_reset_tokens) table
            DB::table('password_reset_tokens')->updateOrInsert(
                ['email' => $data['email']],
                [
                    'token' => $token,
                    'created_at' => Carbon::now()
                ]
            );

            $resetPasswordLink = url('/reset-password?token=' . $token);
            $htmlContent = "
                    <p>Forget Password Email</p>
                    <p>You can reset your password from the link below:</p>
                    <p><a href='{$resetPasswordLink}'>Reset Password Link</a></p>
                ";

            Mail::send([], [], function ($message) use ($data, $resetPasswordLink, $htmlContent) {
                $message->to($data['email'])
                        ->subject('Reset Password')
                        ->html($htmlContent);
            });
        
            return [
                'status'  => 'success',
                'message' => __('auth.reset_link') . $data['email'],
                'code'    => 200
            ];
        }catch(Throwable $e){
            Log::error('error in submit forgetpassword', ['error_message' => $e->getMessage()]);
        }
    }

    //submit reset password
    public function submitResetPasswordForm($data)
    {
        try{
            //check if the email and token exist in the Table
            $record = DB::table('password_reset_tokens')
                    ->where('email', $data['email'])
                    ->where('token', $data['token'])
                    ->first();

            //if the record is not found
            if(!$record){
                return [
                    'status'  => 'error',
                    'message' => __('auth.token_email_err'),
                    'code'    => 400
                ];
            }    

            //Update the User Password
            User::where('email', $data['email'])
                ->update(['password' => Hash::make($data['password'])]);

            //if the password is updated the reset token is removed form the table
            DB::table('password_reset_tokens')
                ->where('email', $data['email'])
                ->delete();

             return [
                'status'  => 'success',
                'message' => __('auth.reset_password'),
                'code'    => 200
            ];
        }catch(Throwable $e){
            Log::error('error in reset password', ['error_message' => $e->getMessage()]);
        }
    }

    //Change Password(after Login)
    public function changePassword($data)
    {
        try{
            $currentPassword = $data['current_password'];
            $newPassword = $data['new_password'];

            $user = Auth::user();

            //check the current password is same the user password
            if(!Hash::check($currentPassword, $user->password)){
                return [
                    'status'    => false,
                    'code'      => 400,
                    'message'   => __('auth.change_password_err')
                ];
            }

            //update the password
            $user->password = Hash::make($newPassword);
            $user->save();

            return [
                'status'  => true,
                'code'    => 200,
                'message' => __('auth.change_password_success')
            ];
        }catch(Throwable $e){
            Log::error('error in change password', ['error_message' => $e->getMessage()]);
        }
    }
}