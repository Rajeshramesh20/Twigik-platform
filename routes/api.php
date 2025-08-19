<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\AuthController;
// Route::get('/user', function (Request $request) {
//     return $request->user();
// })->middleware('auth:sanctum');

Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'userLogin']);
Route::get('/verify-email', [AuthController::class, 'verifyEmail']);
Route::post('/forgot-password', [AuthController::class, 'submitForgetPassword']);
Route::post('/reset-password', [AuthController::class, 'submitResetPassword']);

Route::middleware(['auth:api'])->group(function () {
    Route::post('/logout', [AuthController::class, 'userLogout']);
    Route::post('/change-password', [AuthController::class, 'changePassword']);
});
