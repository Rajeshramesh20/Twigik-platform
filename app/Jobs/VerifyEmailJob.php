<?php

namespace App\Jobs;

use App\Services\CommonService;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;

class verifyEmailJob implements ShouldQueue
{
    use Queueable;

    protected $data;
    protected $verificationLink;

    public function __construct(array $data, string $verificationLink)
    {
        $this->data = $data;
        $this->verificationLink = $verificationLink;
    }

    /**
     * Execute the job.
     */
    public function handle(CommonService $commonService)
    {
        $commonService->sendVerifyEmail($this->data, $this->verificationLink);
    }
}
