<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Unique;

class RegisterRequest extends FormRequest
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
        return [
            //User fields
            'user_uuid'       => 'nullable|uuid',
            'name'            => 'required|string|max:255',
            'email'           => 'required|email|Unique:users,email',
            'password'        => 'required|string|min:6',
            'is_verified'     => 'boolean',
            'is_active'       => 'boolean',
            'last_login_at'   => 'nullable|date',
            'failed_attempts' => 'nullable|integer|min:0',
            'recovery_token'  => 'nullable|string|max:255',
            'is_deleted'      => 'boolean',


            // Organization fields
            'org_name'        => 'required|string|max:255|Unique:organizations,org_name',
            'db_name'         => 'nullable|string|max:255',
            'db_user'         => 'nullable|string|max:255',
            'db_pswd'         => 'nullable|string|max:255',
            'status'          => 'boolean',
        ];
    }

    public function messages(): array
    {
        return [
            // User messages
            'name.required'     =>  'The name is required.' ,
            'email.required'    =>  'The email address is required.',
            'email.email'       =>  'Please enter a valid email address.',
            'email.unique'      =>  'This email address is already registered.',
            'password.required' =>  'Password is required.',


            // Organization messages
            'org_name.required'    => 'The organization name is required.',
        ];
    }
}
