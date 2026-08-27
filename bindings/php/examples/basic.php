<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Antech.php';

use Antech\Kdf\Antech;
use Antech\Kdf\Config;

$stored = Antech::hash('correct_horse_battery_staple');
assert(Antech::verify('correct_horse_battery_staple', $stored));

$cfg = Config::default();
$cfg->memoryKib = 1024;
$custom = Antech::hashWithConfig('pw', $cfg);
echo 'needs_rehash ', Antech::needsRehash($custom) ? 'true' : 'false', PHP_EOL;
echo $stored, PHP_EOL;
