<?php

namespace App\Services;

use App\Models\User;
use App\Models\Auth\AuthToken;
use App\Models\Auth\Organization;
use App\Models\Auth\OrganizationUser;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Support\Carbon;

class AuthServices
{
  public function register(array $data){
        
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

        $organization = Organization::create([
            'org_name'   => $data['org_name'], 
            'db_name'    => $data['db_name'] ?? null,
            'db_user'    => $data['db_user'] ?? null,
            'db_pswd'    => $data['db_pswd'] ?? null,
            'status'     => $data['status'] ?? true,
            'is_deleted' => false,
        ]);

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

        // // Send email 
        // Mail::send('emails.verify', ['link' => $verificationLink, 'name' => $data['name']], function ($message) use ($data) {
        //     $message->to($data['email']);
        //     $message->subject('Verify Your Email');
        // });
        Mail::send([], [], function ($message) use ($data, $verificationLink) {
            $message->to($data['email'])
                ->subject('Verify Your Email')
                ->html(
                    "Hi {$data['name']},<br><br>" .
                        "Please verify your email by clicking the link below:<br>" .
                        "<a href='{$verificationLink}'>Verify Email</a><br><br>" .
                        "This link will expire in 30 minutes.<br><br>" .
                        "Regards,<br>Your App Team"
                );
        });

        return $user;
  }

  
    public function verifyEmail($token)
    {
        $authToken = AuthToken::where('token', $token)
            ->whereNull('revoked_at')
            ->first();

        Log::error('auth token' . $authToken);  

        if (!$authToken) {
            return [
                'status'  => false,
                'message' => 'Invalid or already used token',
                'code'    => 400
            ];
        }

        if (Carbon::now()->greaterThan($authToken->expires_at)) {
            return [
                'status'  => false,
                'message' => 'Token expired',
                'code'    => 400
            ];
        }

        $user = $authToken->user;
        
        $user->update([
            'is_verified' => true,
            'email_verified_at' => Carbon::now()
        ]);

        $authToken->update(['revoked_at' => Carbon::now()]);

        return [
            'status'  => true,
            'message' => 'Email verified successfully',
            'code'    => 200
        ];
    }


        public function userLogin($data){

            $userData = [
                'email'    => $data['email'],
                'password' => $data['password'],
            ];

            if(!Auth::attempt($userData)){
                return [
                    'status'  => false,
                    'message' => 'Invalid credentials provided',
                    'code'    => 404
                ];
            }

            $user = User::where('email', $data['email'])->first();

            if(!$user->is_verified){              
                return [
                    'status'  => false,
                    'message' => 'Email does not verified!',
                    'code'    => 400
                ];
            }

            $tokenResult = $user->createToken('userToken')->accessToken;

            return [
                    'status' => true,
                    'message' => 'Login Successfully',
                    'data'   => auth()->user(),
                    'token'  => $tokenResult,
                    'code'   => 200
            ];
        }

        //logout
        public function userLogout($request){

            $request->user()->token()->revoke();

             return [
                'status'  => true,
                'message' => 'Successfully logged out',
                'code'    => 200
            ];
        }


    //send forgot password link to mail
    public function submitForgotPasswordForm($data)
    {
        $user = User::where('email', $data['email'])->first();

        if(!$user){
            return [
                'status' => 'error',
                'message' => 'Email Is Not Found',
                'code'    => 404
            ];
        }

        $token = Str::random(64);

        DB::table('password_reset_tokens')->updateOrInsert(
            ['email' => $data['email']],
            [
                'token' => $token,
                'created_at' => Carbon::now()
            ]
        );

        $resetPasswordLink = url('/reset-password?token=' . $token);

        Mail::send([], [], function ($message) use ($data, $resetPasswordLink) {
            $message->to($data['email'])
                    ->subject('Reset Password')
            ->html(
                    "forget Password Email" .
                    "you can reset password from below link:".
                    "<a href='{$resetPasswordLink}'>Reset Password Link</a><br><br>" .
                    "Regards,<br>Your App Team"
                );
        });
        
        return [
            'status'  => 'success',
            'message' => 'We have emailed you a reset password link.',
            'code'    => 200
        ];
    }


    public function submitResetPasswordForm($data)
    {
        //check if the email and token exist in the Table
        $record = DB::table('password_reset_tokens')
                ->where('email', $data['email'])
                ->where('token', $data['token'])
                ->first();

        if(!$record){
            return [
                'status'  => 'error',
                'message' => 'Invalid token or email.',
                'code'    => 400
            ];
        }    

        //Update the User Password
        User::where('email', $data['email'])
            ->update(['password' => Hash::make($data['password'])]);

        DB::table('password_reset_tokens')
            ->where('email', $data['email'])
            ->delete();

         return [
            'status'  => 'success',
            'message' => 'Password has been successfully reset.',
            'code'    => 200
        ];
    }

    //Change Password(after Login)
    public function changePassword($data){

            $currentPassword = $data['current_password'];
            $newPassword = $data['new_password'];

            $user = Auth::user();

            if(!Hash::check($currentPassword, $user->password)){
                return [
                    'status'    => false,
                    'code'      => 400,
                    'message'   => 'Current password is incorrect'
                ];
            }

            $user->password = Hash::make($newPassword);
            $user->save();

            return [
                'status'  => true,
                'code'    => 200,
                'message' => 'Password updated successfully'
            ];
    }
}