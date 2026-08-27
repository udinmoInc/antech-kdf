# Antech KDF — PHP

Thin FFI wrapper (`ext-ffi`). Build the native library first:

```bash
./sdk/scripts/build-native.sh   # or build-native.ps1 on Windows
composer install -d bindings/php
php bindings/php/examples/basic.php
```

Requires PHP 8.1+ with `extension=ffi` enabled (`ffi.enable=true` in php.ini for CLI).

```php
use Antech\Kdf\Antech;

$stored = Antech::hash('correct_horse_battery_staple');
assert(Antech::verify('correct_horse_battery_staple', $stored));
```

Optional secret / associated data: `null` = absent; `''` = present-but-empty (see `bindings/c/antech_kdf.h`).
