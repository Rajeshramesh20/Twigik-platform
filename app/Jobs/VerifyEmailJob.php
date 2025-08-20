<?php

namespace App\Jobs;

use App\Services\CommonService;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;

class VerifyEmailJob implements ShouldQueue
{
    use Queueable;

    protected $data;
    protected $verificationLink;
    protected string $type;

    public function __construct(array $data, string $verificationLink, string $type)
    {
        $this->data = $data;
        $this->verificationLink = $verificationLink;
        $this->type = $type;
    }

    /**
     * Execute the job.
     */
    public function handle(CommonService $CommonService): void
    {

        if ($this->type === 'verify') {
            $CommonService->sendVerifyEmail($this->data, $this->verificationLink);
        } elseif ($this->type === 'forgot') {
            $CommonService->sendForgotPasswordEmail($this->data, $this->verificationLink);
        }
    }

    }

