<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\AuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });

Route::POST('/auth/signup', [AuthController::class, 'register']);
Route::POST('/auth/login', [AuthController::class, 'userLogin']);
Route::get('/verify-email', [AuthController::class, 'verifyEmail']);
Route::POST('/auth/reset-password', [AuthController::class, 'submitForgetPassword']);
Route::POST('/auth/reset-password/confirm', [AuthController::class, 'submitResetPassword']);


Route::controller(AuthController::class)        
        ->as('')
        ->middleware(['auth:api'])
        ->group(function () {


    Route::POST('/auth/logout', 'userLogout');
    Route::POST('/auth/change-password', 'changePassword');
              
});
