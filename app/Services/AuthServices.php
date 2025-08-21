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
use App\Services\CommonService;



use App\Http\Resources\Auth\LoginResource;
use App\Http\Resources\Auth\OrgResource;

use App\Jobs\verifyEmailJob;

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

            $Organization_token = Str::random(64);
            //create Organization Table
            $organization = Organization::create([
                'uuid'       => $data['uuid'] ?? Str::uuid()->toString(),
                'org_name'   => $data['org_name'],
                'db_name'    => $data['db_name'] ?? str::slug($data['org_name']),
                'db_user'    => $data['db_user'] ?? str::slug($data['org_name']) . '_user',
                'db_pswd'    => $data['db_pswd'] ?? null,
                'token'      => $Organization_token,
                'status'     => $data['status'] ?? false,
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

            verifyEmailJob::dispatch($data, $verificationLink, 'verify');

            return $user;
        } catch (Throwable $e) {
            Log::error('Registration failed', ['error_message' => $e->getMessage()]);
        }
    }

    //email verification
    public function verifyEmail($token)
    {
        try {

            $authToken = AuthToken::findActiveByToken($token);

            Log::error('auth token' . $authToken);
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




            $organization = $user->organizations()->first();

            $common = new CommonService();
            if ($organization) {
                //Create dynamic DB
                $common->activateOrganization($organization);
            }

            $authToken->update(['revoked_at' => Carbon::now()]);

            return [
                'status'  => true,
                'message' => __('auth.mail_verification'),
                'code'    => 200
            ];
        } catch (Throwable $e) {

            Log::error('Error in verify email', ['error_message' => $e->getMessage()]);
        }
    }

    //user login
    public function userLogin($data)
    {
        try {

            $user =  User::findBy('email', $data['email']);

            // Check if user is found
            if (!$user) {
                return [
                    'status'  => false,
                    'message' => __('auth.login_failed'),
                    'code'    => 401
                ];
            }

            // Check if user is locked
            if ($user->lockout_time && $user->lockout_time > now()) {
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

            if (!Auth::attempt($userData)) {

                $user->increment('failed_attempts');

                //Lock Login in 5 minutes
                if ($user->failed_attempts >= 5) {
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
                ];
            }
            $user->update([
                'last_login_at'   => Carbon::now(),
                'lockout_time'    => null
            ]);

            $tokenResult = $user->createToken('userToken');

            $token = $tokenResult->accessToken;
            $tokenExpiry = $tokenResult->token->expires_at;

            Log::error('organization', ['organization' =>  $user->organizations]);
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
        } catch (Throwable $e) {
            Log::error('Login Failed', ['error_message' => $e->getMessage()]);
        }
    }


    //logout 
    public function userLogout($request)
    {
        try {
            // token is revoke(1)
            $request->user()->token()->revoke();

            return [
                'status'  => true,
                'message' => __('auth.logout'),
                'code'    => 200
            ];
        } catch (Throwable $e) {
            Log::error('Error: logout failed', ['error_message' => $e->getMessage()]);
        }
    }


    //send forgot password link to mail
    public function submitForgotPasswordForm($data)
    {

        try {
            $common = new CommonService();
            $user =  User::findBy('email', $data['email']);

            // Check if user email is found
            if (!$user) {
                return [
                    'status' => 'error',
                    'message' => __('auth.email_error'),
                    'code'    => 404
                ];
            }

            //create random token
            $token = Str::random(64);

            //insert the token&email into (password_reset_tokens) table
            $common->updateOrInsert(
                'password_reset_tokens',
                ['email' => $data['email']],
                ['token' => $token, 'created_at' => Carbon::now()]
            );

            $resetPasswordLink = url('/reset-password?token=' . $token);
            verifyEmailJob::dispatch($data, $resetPasswordLink, 'forgot');
            
            return [
                'status'  => 'success',
                'message' => __('auth.reset_link') . $data['email'],
                'code'    => 200
            ];
        } catch (Throwable $e) {
            Log::error('error in submit forgetpassword', ['error_message' => $e->getMessage()]);
        }
    }

    //submit reset password
    public function submitResetPasswordForm($data)
    {

        try {
            $common = new CommonService();

            //check if the email and token exist in the Table
            $record = $common->findRecord('password_reset_tokens', [
                'email' => $data['email'],
                'token' => $data['token'],
            ]);


            //if the record is not found
            if (!$record) {
                return [
                    'status'  => 'error',
                    'message' => __('auth.token_email_err'),
                    'code'    => 400
                ];
            }

            $user =  User::findBy('email', $data['email']);

            //Update the User Password
            if ($user) {
                $user->update(['password' => Hash::make($data['password'])]);
            }

            //delete the password reset token
            $common->deleteRecord('password_reset_tokens', [
                'email' => $data['email'],
            ]);

            return [
                'status'  => 'success',
                'message' => __('auth.reset_password'),
                'code'    => 200
            ];
        } catch (Throwable $e) {
            Log::error('error in reset password', ['error_message' => $e->getMessage()]);
        }
    }


    //Change Password(after Login)
    public function changePassword($data)
    {
        try {
            $currentPassword = $data['current_password'];
            $newPassword = $data['new_password'];

            $user = Auth::user();

            //check the current password is same the user password
            if (!Hash::check($currentPassword, $user->password)) {
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
        } catch (Throwable $e) {
            Log::error('error in change password', ['error_message' => $e->getMessage()]);
        }
    }
}
