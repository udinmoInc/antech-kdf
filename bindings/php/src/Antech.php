<?php

declare(strict_types=1);

/** Thin PHP FFI over libantech_kdf (see bindings/c/antech_kdf.h). */

namespace Antech\Kdf;

final class PackageInfo
{
    public const VERSION = '0.1.0';
}

final class AntechException extends \RuntimeException
{
}

final class Config
{
    public int $memoryKib = 16384;
    public int $saltLength = 16;
    public int $blockSize = 32;
    public int $fanIn = 2;
    public int $graph = 3;
    public int $outputLength = 32;

    public static function default(): self
    {
        $lib = Native::lib();
        $c = $lib->new('AntechConfig');
        Native::raise($lib->antech_config_default(\FFI::addr($c)));
        $cfg = new self();
        $cfg->memoryKib = (int) $c->memory_kib;
        $cfg->saltLength = (int) $c->salt_length;
        $cfg->blockSize = (int) $c->block_size;
        $cfg->fanIn = (int) $c->fan_in;
        $cfg->graph = (int) $c->graph;
        $cfg->outputLength = (int) $c->output_length;
        return $cfg;
    }

    /** @return \FFI\CData */
    public function toC(): object
    {
        $c = Native::lib()->new('AntechConfig');
        $c->memory_kib = $this->memoryKib;
        $c->salt_length = $this->saltLength;
        $c->block_size = $this->blockSize;
        $c->fan_in = $this->fanIn;
        $c->graph = $this->graph;
        $c->output_length = $this->outputLength;
        return $c;
    }
}

final class RehashPolicy
{
    public int $minimumMemoryKib = 16384;
    public int $preferredMemoryKib = 16384;
    public int $preferredFanIn = 2;
    public int $preferredOutputLength = 32;
    public bool $preferredSecretRequired = false;
    public bool $preferredAssociatedData = false;

    public static function default(): self
    {
        $lib = Native::lib();
        $p = $lib->new('AntechRehashPolicy');
        Native::raise($lib->antech_rehash_policy_default(\FFI::addr($p)));
        $pol = new self();
        $pol->minimumMemoryKib = (int) $p->minimum_memory_kib;
        $pol->preferredMemoryKib = (int) $p->preferred_memory_kib;
        $pol->preferredFanIn = (int) $p->preferred_fan_in;
        $pol->preferredOutputLength = (int) $p->preferred_output_length;
        $pol->preferredSecretRequired = ((int) $p->preferred_secret_required) !== 0;
        $pol->preferredAssociatedData = ((int) $p->preferred_associated_data) !== 0;
        return $pol;
    }

    /** @return \FFI\CData */
    public function toC(): object
    {
        $p = Native::lib()->new('AntechRehashPolicy');
        $p->minimum_memory_kib = $this->minimumMemoryKib;
        $p->preferred_memory_kib = $this->preferredMemoryKib;
        $p->preferred_fan_in = $this->preferredFanIn;
        $p->preferred_output_length = $this->preferredOutputLength;
        $p->preferred_secret_required = $this->preferredSecretRequired ? 1 : 0;
        $p->preferred_associated_data = $this->preferredAssociatedData ? 1 : 0;
        return $p;
    }
}

/** @internal */
final class Native
{
    private static ?\FFI $ffi = null;

    public static function lib(): \FFI
    {
        if (self::$ffi !== null) {
            return self::$ffi;
        }
        if (!extension_loaded('ffi')) {
            throw new AntechException('PHP FFI extension is required (enable extension=ffi)');
        }
        $path = self::findLibrary();
        $cdef = <<<'C'
            typedef struct AntechConfig {
                uint32_t memory_kib;
                uint32_t salt_length;
                uint32_t block_size;
                uint32_t fan_in;
                uint32_t graph;
                uint32_t output_length;
            } AntechConfig;
            typedef struct AntechRehashPolicy {
                uint32_t minimum_memory_kib;
                uint32_t preferred_memory_kib;
                uint32_t preferred_fan_in;
                uint32_t preferred_output_length;
                uint32_t preferred_secret_required;
                uint32_t preferred_associated_data;
            } AntechRehashPolicy;
            const char* antech_version(void);
            int antech_config_default(AntechConfig* out);
            int antech_rehash_policy_default(AntechRehashPolicy* out);
            int antech_hash_bytes(const uint8_t* password, size_t password_len, char** out_hash);
            int antech_hash_with_config_bytes(const uint8_t* password, size_t password_len, const AntechConfig* config, char** out_hash);
            int antech_hash_with_config_and_salt(const uint8_t* password, size_t password_len, const uint8_t* salt, size_t salt_len, const AntechConfig* config, char** out_hash);
            int antech_hash_with_inputs_bytes(const uint8_t* password, size_t password_len, const AntechConfig* config, const uint8_t* secret, size_t secret_len, const uint8_t* associated_data, size_t associated_data_len, char** out_hash);
            int antech_hash_with_inputs_and_salt(const uint8_t* password, size_t password_len, const uint8_t* salt, size_t salt_len, const AntechConfig* config, const uint8_t* secret, size_t secret_len, const uint8_t* associated_data, size_t associated_data_len, char** out_hash);
            int antech_verify_bytes(const uint8_t* password, size_t password_len, const char* encoded_hash);
            int antech_verify_with_inputs_bytes(const uint8_t* password, size_t password_len, const char* encoded_hash, const uint8_t* secret, size_t secret_len, const uint8_t* associated_data, size_t associated_data_len);
            int antech_needs_rehash(const char* encoded_hash, int* out_needs_rehash);
            int antech_needs_rehash_with_policy(const char* encoded_hash, const AntechRehashPolicy* policy, int* out_needs_rehash);
            void antech_free(char* ptr);
        C;
        self::$ffi = \FFI::cdef($cdef, $path);
        return self::$ffi;
    }

    public static function findLibrary(): string
    {
        $env = getenv('ANTECH_KDF_LIB') ?: '';
        $root = dirname(__DIR__, 3);
        $names = PHP_OS_FAMILY === 'Windows'
            ? ['antech_kdf.dll', 'antech_kdf_ffi.dll']
            : (PHP_OS_FAMILY === 'Darwin'
                ? ['libantech_kdf.dylib', 'libantech_kdf_ffi.dylib']
                : ['libantech_kdf.so', 'libantech_kdf_ffi.so']);
        $dirs = array_filter([
            is_file($env) ? dirname($env) : ($env !== '' ? $env : null),
            $root . DIRECTORY_SEPARATOR . 'sdk' . DIRECTORY_SEPARATOR . 'native',
            $root . DIRECTORY_SEPARATOR . 'target' . DIRECTORY_SEPARATOR . 'release',
            $root . DIRECTORY_SEPARATOR . 'target' . DIRECTORY_SEPARATOR . 'debug',
            __DIR__ . DIRECTORY_SEPARATOR . 'native',
        ]);
        if (is_file($env)) {
            return $env;
        }
        foreach ($dirs as $dir) {
            foreach ($names as $n) {
                $p = $dir . DIRECTORY_SEPARATOR . $n;
                if (is_file($p)) {
                    return $p;
                }
            }
        }
        throw new AntechException(
            'native library not found; run sdk/scripts/build-native.(sh|ps1) or set ANTECH_KDF_LIB'
        );
    }

    public static function raise(int $st): void
    {
        if ($st === 0) {
            return;
        }
        $msg = match ($st) {
            -1 => 'invalid input',
            -2 => 'invalid hash',
            -4 => 'invalid config',
            default => "internal error ($st)",
        };
        throw new AntechException($msg);
    }

    public static function take(object $out): string
    {
        $ptr = $out->cdata;
        if ($ptr === null) {
            throw new AntechException('null string');
        }
        $s = \FFI::string($ptr);
        self::lib()->antech_free($ptr);
        return $s;
    }

    /** @return array{0:?\FFI\CData,1:int} */
    public static function bytesPtr(string $data): array
    {
        if ($data === '') {
            return [null, 0];
        }
        $buf = self::lib()->new('uint8_t[' . strlen($data) . ']');
        \FFI::memcpy($buf, $data, strlen($data));
        return [$buf, strlen($data)];
    }

    /** null = absent; '' = present empty (see antech_kdf.h). @return array{0:?\FFI\CData,1:int} */
    public static function optPtr(?string $data): array
    {
        if ($data === null) {
            return [null, 0];
        }
        if ($data === '') {
            $scratch = self::lib()->new('uint8_t[1]');
            $scratch[0] = 0;
            return [$scratch, 0];
        }
        return self::bytesPtr($data);
    }

    public static function takeHash(callable $call): string
    {
        $out = self::lib()->new('char*');
        self::raise((int) $call(\FFI::addr($out)));
        return self::take($out);
    }

    public static function asVerified(int $st): bool
    {
        if ($st === 0) {
            return true;
        }
        if ($st === 1) {
            return false;
        }
        self::raise($st);
        return false;
    }

    public static function readNeedsRehash(callable $call): bool
    {
        $out = self::lib()->new('int');
        self::raise((int) $call(\FFI::addr($out)));
        return ((int) $out->cdata) !== 0;
    }
}

final class Antech
{
    public const GRAPH_COMBINED_FRONTIER = 3;

    public static function version(): string
    {
        $v = Native::lib()->antech_version();
        return $v !== null ? \FFI::string($v) : PackageInfo::VERSION;
    }

    public static function hash(string $password): string
    {
        [$ptr, $len] = Native::bytesPtr($password);
        return Native::takeHash(fn ($out) => Native::lib()->antech_hash_bytes($ptr, $len, $out));
    }

    public static function hashWithConfig(string $password, Config $config): string
    {
        [$ptr, $len] = Native::bytesPtr($password);
        $cfg = $config->toC();
        return Native::takeHash(
            fn ($out) => Native::lib()->antech_hash_with_config_bytes($ptr, $len, \FFI::addr($cfg), $out)
        );
    }

    public static function hashWithConfigAndSalt(string $password, string $salt, Config $config): string
    {
        [$pw, $pwLen] = Native::bytesPtr($password);
        [$saltPtr, $saltLen] = Native::bytesPtr($salt);
        $cfg = $config->toC();
        return Native::takeHash(
            fn ($out) => Native::lib()->antech_hash_with_config_and_salt(
                $pw, $pwLen, $saltPtr, $saltLen, \FFI::addr($cfg), $out
            )
        );
    }

    public static function hashWithInputs(
        string $password,
        Config $config,
        ?string $secret = null,
        ?string $associatedData = null
    ): string {
        [$pw, $pwLen] = Native::bytesPtr($password);
        [$sec, $secLen] = Native::optPtr($secret);
        [$ad, $adLen] = Native::optPtr($associatedData);
        $cfg = $config->toC();
        return Native::takeHash(
            fn ($out) => Native::lib()->antech_hash_with_inputs_bytes(
                $pw, $pwLen, \FFI::addr($cfg), $sec, $secLen, $ad, $adLen, $out
            )
        );
    }

    public static function hashWithInputsAndSalt(
        string $password,
        string $salt,
        Config $config,
        ?string $secret = null,
        ?string $associatedData = null
    ): string {
        [$pw, $pwLen] = Native::bytesPtr($password);
        [$saltPtr, $saltLen] = Native::bytesPtr($salt);
        [$sec, $secLen] = Native::optPtr($secret);
        [$ad, $adLen] = Native::optPtr($associatedData);
        $cfg = $config->toC();
        return Native::takeHash(
            fn ($out) => Native::lib()->antech_hash_with_inputs_and_salt(
                $pw, $pwLen, $saltPtr, $saltLen, \FFI::addr($cfg), $sec, $secLen, $ad, $adLen, $out
            )
        );
    }

    public static function verify(string $password, string $encodedHash): bool
    {
        [$ptr, $len] = Native::bytesPtr($password);
        return Native::asVerified((int) Native::lib()->antech_verify_bytes($ptr, $len, $encodedHash));
    }

    public static function verifyWithInputs(
        string $password,
        string $encodedHash,
        ?string $secret = null,
        ?string $associatedData = null
    ): bool {
        [$pw, $pwLen] = Native::bytesPtr($password);
        [$sec, $secLen] = Native::optPtr($secret);
        [$ad, $adLen] = Native::optPtr($associatedData);
        return Native::asVerified((int) Native::lib()->antech_verify_with_inputs_bytes(
            $pw, $pwLen, $encodedHash, $sec, $secLen, $ad, $adLen
        ));
    }

    public static function needsRehash(string $encodedHash): bool
    {
        return Native::readNeedsRehash(
            fn ($out) => Native::lib()->antech_needs_rehash($encodedHash, $out)
        );
    }

    public static function needsRehashWithPolicy(string $encodedHash, RehashPolicy $policy): bool
    {
        $p = $policy->toC();
        return Native::readNeedsRehash(
            fn ($out) => Native::lib()->antech_needs_rehash_with_policy($encodedHash, \FFI::addr($p), $out)
        );
    }
}
