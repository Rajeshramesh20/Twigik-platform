<?php

namespace App\Services;


use Illuminate\Support\Facades\DB;

use App\Jobs\CreateOrganizationDatabaseJob;
use App\Models\Auth\Organization;

class CommonService
{
    public function findRecord($table, $conditions)
    {
        return DB::table($table)
            ->where($conditions)
            ->first();
    }

    public function deleteRecord($table, $conditions)
    {
        return DB::table($table)
        ->where($conditions)
        ->delete();
    }

    public function updateOrInsert($table, $conditions, $values)
    {
        return DB::table($table)
        ->updateOrInsert($conditions, $values);
    }


    public function activateOrganization(Organization $organization)
    {
        // Mark organization as active
        $organization->update(['status' => true]);

        // Queue DB creation
        CreateOrganizationDatabaseJob::dispatch($organization);
    }


    public function sendVerifyEmail($data, $verificationLink){

        $template = EmailVerify::where('key', 'verify_email')->first();

        $bodyContent = str_replace(
            ['{{name}}', '{{verification_link}}'],
            [$this->data['name'], $this->verificationLink],
            $template->body
        );

        // Send email
        Mail::send([], [], function ($message) use ($data, $template, $bodyContent) {
            $message->to($data['email'])
                ->subject($template->subject)
                ->html($bodyContent);
        });   
    }
   
}