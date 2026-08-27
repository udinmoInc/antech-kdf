# Backend sketch: register/login with the PHP SDK.

<?php

require_once __DIR__ . '/../../bindings/php/src/Antech.php';

use Antech\Kdf\Antech;

function register_user(string $password): string
{
    return Antech::hash($password);
}

function login_user(string $password, string $storedHash): bool
{
    return Antech::verify($password, $storedHash);
}
