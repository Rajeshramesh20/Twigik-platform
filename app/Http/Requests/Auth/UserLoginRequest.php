<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\DB;

class UserLoginRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        // return [
        //     'email' => 'required|email|exists:users,email|email_verified_at,true',
        //     'password' => 'required|min:6'
        // ];
        return [
            'email' => [
                'required',
                'email',
                function ($attribute, $value, $fail) {
                    $user = DB::table('users')->where('email', $value)->first();
                    if (!$user) {
                        $fail('The selected email is invalid.');
                    } elseif (!$user->is_verified) {
                        $fail('Email is not verified!');
                    }
                },
            ],
            'password' => 'required|min:6',
        ];
    }
}
