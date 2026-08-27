# Antech KDF — Perl

Thin FFI wrapper (`FFI::Platypus`). Build the native library first:

```bash
./sdk/scripts/build-native.sh   # or build-native.ps1 on Windows
cpanm FFI::Platypus
perl -Ibindings/perl/lib bindings/perl/examples/basic.pl
```

```perl
use Antech::Kdf qw(hash verify);
my $stored = hash('correct_horse_battery_staple');
die unless verify('correct_horse_battery_staple', $stored);
```

Optional secret / associated data: `undef` = absent; `''` = present-but-empty (see `bindings/c/antech_kdf.h`).
