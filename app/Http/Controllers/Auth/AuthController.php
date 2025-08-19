<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\DB;
use Illuminate\Http\Request;
use App\Http\Requests\Auth\RegisterRequest;
use App\Http\Requests\Auth\UserLoginRequest;
use App\Http\Requests\Auth\ForgetPasswordRequest;
use App\Http\Requests\Auth\ResetPasswordRequest;
use App\Http\Requests\Auth\ChangePasswordRequest;
use Exception;
use App\Services\AuthServices;
use Throwable;

class AuthController extends Controller
{
    //User Registration
    public function register(RegisterRequest $request, AuthServices $auth_services)
    {

        DB::beginTransaction();
        
        try {
          $validated = $request->validated();
         
           $user = $auth_services->register($validated);

            DB::commit();

            if ($user) {
                return response([
                    'status'  => true,
                    'data'    => $user,
                    'message' => 'User and organization registered successfully.',
                ], 201);
            }

    }catch(Throwable  $e){

            DB::rollBack();

            Log::error('Registration failed', ['error_message' => $e->getMessage()]);
            return response([
                'status' => false, 
                'message' => 'Registration failed. Please try again later.'
            ], 500);
    }
     
 }

    //Email Verification
    public function verifyEmail(Request $request, AuthServices $auth_services)
    {
        try {
            
            $token = $request->token;

            if (!$token) {
                return response()->json([
                    'status'  => false,
                    'message' => 'Token is required'
                ], 400);
            }

            $result = $auth_services->verifyEmail($token);

            return response()->json([
                'status'  => $result['status'],
                'message' => $result['message']
            ], $result['code']);

        } catch (Exception $e) {
            return response()->json([
                'status'  => false,
                'message' => 'Something went wrong',
                'error'   => $e->getMessage()
            ], 500);
        }
    }



    // User Login 
    public function userLogin(UserLoginRequest $request, AuthServices $login)
    {

      try {
        $validatedData = $request->validated();
        $data = $login->userLogin($validatedData);

            if (!$data['status']) {
                return response()->json([
                    'status'  => $data['status'],
                    'message' => $data['message']
                ], $data['code']);
            }

            return response()->json([
                'status'  => $data['status'],
                'message' => $data['message'],
                'user'    => $data['data'],
                'orgs'    => $data['organization'],
                'token'   => $data['token'],
                'session' => [
                    'expires_in' => $data['expires_in']
                ],
            ], $data['code']);

    } catch (Throwable $e) {
        Log::error('Error In login User: ' . $e->getMessage());

        return response()->json([
            'status'  => false,
            'message' => 'Login Failed',
            'error'   => $e->getMessage()
        ], 500);
     }
 }


    // User Logout 
    public function userLogout(Request $request, AuthServices $logout)
    {
            try{
             $userLogout = $logout->userLogout($request);

             if($userLogout){
                return response()->json([
                    'status'  => $userLogout['status'],
                    'message' => $userLogout['message']
                ],$userLogout['code']);
             }

            }catch(Throwable $e){
                Log::error('Error In login User: ' . $e->getMessage());

                return response()->json([
                    'status'  => false,
                    'message' => 'Logout Failed',
                    'error'   => $e->getMessage()
                ], 500);
            }
        }


    //forgot password
    public function submitForgetPassword(ForgetPasswordRequest $request, AuthServices $AuthService)
        {
            try{
                $data = $request->validated();
                $result = $AuthService->submitForgotPasswordForm($data);
                if($result){
                    return response()->json([
                        'status' => $result['status'],
                        'message' => $result['message']
                    ], $result['code']);
                }
            }catch(Exception $e){
                return response()->json([
                    'success' => false,
                    'message' => 'failed to send email.',
                    'error' => $e->getMessage()
                ]);
            }
        }


    // send reset password link
    public function submitResetPassword(ResetPasswordRequest $request, AuthServices $authService)
    {
        try {
            $data = $request->validated();
            $data['token'] = $request->token;
            $result = $authService->submitResetPasswordForm($data);

            return response()->json([
                'status' => $result['status'],
                'message' => $result['message'],
            ], $result['code']);

        } catch (Exception $e) {
            return response()->json([
                'status' => false,
                'message' => 'failed to change password.',
                'error' => $e->getMessage()
            ]);
        }
    }


    //change Password(after login)
    public function changePassword(ChangePasswordRequest $request, AuthServices $userPassword)
    {
        try{
            $changeUserPassword = $request->validated();

            $result = $userPassword->changePassword($changeUserPassword);

            return response()->json([
                'status'  => $result['status'],
                'message' => $result['message']
            ], $result['code']);
            
        }catch(Exception $e){
            Log::error('error in change password' . $e->getMessage());
            return response()->json([
                'status' => false,
                'message' => 'error in change password'
            ]);
        }
}

}