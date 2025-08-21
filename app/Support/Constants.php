<?php

namespace App\Support;

class Constants
{
    public const SUCCESS = 200;

    public const CREATED  = 201;

    public const BAD_REQUEST  = 400;

    public const UNAUTHORIZED  = 401;

    public const FORBIDDEN  = 403;

    public const NOT_FOUND  = 404;

    public const SERVER_ERROR  = 500;

    public const TOO_MANY_REQUESTS = 429;

    public const RANDOM_TOKEN = 64;

    public const TOKEN_ADD_MINUTES = 30;

    public const LOCKOUT_TIME = 5;

    public const LOGIN_FAILED_ATTEMPTS = 5;

    public const BOOLEAN_FALSE_VALUE = False;
    
    public const BOOLEAN_TRUE_VALUE  = True;
}

?>
