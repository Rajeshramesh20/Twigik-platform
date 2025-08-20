<?php

namespace App\Services;


use Illuminate\Support\Facades\DB;

use App\Jobs\CreateOrganizationDatabaseJob;
use App\Models\Auth\Organization;
use Illuminate\Support\Facades\Mail;
use App\Models\Auth\EmailVerify;



class CommonService
{
    //check if the given column name is found
    public function findRecord($table, $conditions)
    {
        return DB::table($table)
            ->where($conditions)
            ->first();
    }

    //delete the record after the token used
    public function deleteRecord($table, $conditions)
    {
        return DB::table($table)
        ->where($conditions)
        ->delete();
    }

    //update or insert(reset password table)
    public function updateOrInsert($table, $conditions, $values)
    {
        return DB::table($table)
        ->updateOrInsert($conditions, $values);
    }


    //DB creation(Job)
    public function activateOrganization(Organization $organization)
    {
        // Mark organization as active
        $organization->update(['status' => true]);

        // Queue DB creation
        CreateOrganizationDatabaseJob::dispatch($organization);
    }


    //send verify mail link
    public function sendVerifyEmail($data, $verificationLink){

        $template = EmailVerify::where('key', 'verify_email')->first();

        //replace the value 
        $bodyContent = str_replace(
            ['{{name}}', '{{verification_link}}'],
            [$data['name'], $verificationLink],
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