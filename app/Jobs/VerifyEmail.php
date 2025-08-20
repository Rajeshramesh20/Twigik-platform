<?php

namespace App\Jobs;

use App\Services\CommonService;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;

class VerifyEmail implements ShouldQueue
{
    use Queueable;

    protected $data;
    protected $verificationLink;

    public function __construct()
    {
        $this->data = $data;
        $this->verificationLink = $verificationLink
    }

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        $CommonService->sendVerifyEmail($this->data, $this->verificationLink);
    }
}
