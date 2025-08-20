<?php

namespace App\Jobs;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;

class VerifyEmail implements ShouldQueue
{
    use Queueable;

    protected $data;
    protected $resetPasswordLink;

    public function __construct()
    {
        $this->data = $data;
        $this->resetPasswordLink = $resetPasswordLink
    }

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        $template = EmailVerify::where('key', 'verify_email')->first();

        $bodyContent = str_replace(
            ['{{name}}', '{{verification_link}}'],
            [$this->data['name'], $this->verificationLink],
            $template->body
        );

         return Mail::send(subject($template->subject)
                        ->html($bodyContent)
                  );      
    }
}
