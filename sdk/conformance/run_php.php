#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Run conformance vectors through the PHP FFI SDK.
 * Usage: php sdk/conformance/run_php.php
 */

require dirname(__DIR__, 2) . '/bindings/php/src/Antech.php';

use Antech\Kdf\Antech;
use Antech\Kdf\Config;

$root = dirname(__DIR__, 2);
$doc = json_decode(file_get_contents($root . '/sdk/conformance/vectors.json'), true, 512, JSON_THROW_ON_ERROR);
$failed = 0;

function hex_decode_opt(?string $s): ?string
{
    if ($s === null) {
        return null;
    }
    return $s === '' ? '' : hex2bin($s);
}

foreach ($doc['cases'] as $case) {
    $cfg = new Config();
    $c = $case['config'];
    $cfg->memoryKib = (int) $c['memory_kib'];
    $cfg->saltLength = (int) $c['salt_length'];
    $cfg->blockSize = (int) $c['block_size'];
    $cfg->fanIn = (int) $c['fan_in'];
    $cfg->graph = (int) $c['graph'];
    $cfg->outputLength = (int) $c['output_length'];

    $password = hex2bin($case['password_hex']) ?: '';
    $salt = hex2bin($case['salt_hex']) ?: '';
    $hasSecret = array_key_exists('secret_hex', $case);
    $hasAd = array_key_exists('associated_data_hex', $case);
    $secret = $hasSecret ? hex_decode_opt($case['secret_hex']) : null;
    $ad = $hasAd ? hex_decode_opt($case['associated_data_hex']) : null;

    try {
        if ($hasSecret || $hasAd) {
            $encoded = Antech::hashWithInputsAndSalt($password, $salt, $cfg, $secret, $ad);
        } else {
            $encoded = Antech::hashWithConfigAndSalt($password, $salt, $cfg);
        }
        $digest = substr($encoded, strrpos($encoded, '$') + 1);
        if ($digest !== $case['digest_hex']) {
            echo "FAIL {$case['id']}: digest mismatch got={$digest}\n";
            $failed++;
            continue;
        }
        if ($hasSecret || $hasAd) {
            if (!Antech::verifyWithInputs($password, $encoded, $secret, $ad)) {
                echo "FAIL {$case['id']}: verify_with_inputs\n";
                $failed++;
                continue;
            }
        } elseif (!Antech::verify($password, $encoded)) {
            echo "FAIL {$case['id']}: verify\n";
            $failed++;
            continue;
        }
        echo "ok   {$case['id']}\n";
    } catch (Throwable $e) {
        echo "FAIL {$case['id']}: {$e->getMessage()}\n";
        $failed++;
    }
}

$total = count($doc['cases']);
echo ($total - $failed) . "/{$total} passed\n";
exit($failed ? 1 : 0);
