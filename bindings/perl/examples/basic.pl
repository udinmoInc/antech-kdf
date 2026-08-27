#!/usr/bin/env perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Antech::Kdf qw(hash verify needs_rehash config_default hash_with_config);

my $stored = hash('correct_horse_battery_staple');
die "verify failed\n" unless verify('correct_horse_battery_staple', $stored);

my $cfg = config_default();
$cfg->memory_kib(1024);
my $custom = hash_with_config('pw', $cfg);
print "needs_rehash ", (needs_rehash($custom) ? 'true' : 'false'), "\n";
print "$stored\n";
