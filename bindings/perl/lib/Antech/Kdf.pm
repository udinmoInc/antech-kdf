package Antech::Kdf;
# Thin Perl FFI wrapper (bindings/c/antech_kdf.h).

use strict;
use warnings;
use Exporter 'import';
use FFI::Platypus 1.00;
use FFI::Platypus::Buffer qw( scalar_to_buffer );
use FFI::Platypus::Memory qw( free );
use File::Spec;
use File::Basename qw( dirname );
use Config;

our $VERSION = '0.1.0';
our @EXPORT_OK = qw(
  version hash hash_with_config hash_with_config_and_salt
  hash_with_inputs hash_with_inputs_and_salt
  verify verify_with_inputs needs_rehash needs_rehash_with_policy
  config_default rehash_policy_default
);

use constant GRAPH_COMBINED_FRONTIER => 3;

my $ffi;
my $lib_path;

sub _repo_root {
  File::Spec->catdir(dirname(__FILE__), '..', '..', '..');
}

sub _library_names {
  return ('antech_kdf.dll', 'antech_kdf_ffi.dll') if $^O =~ /MSWin32|cygwin|msys/i;
  return ('libantech_kdf.dylib', 'libantech_kdf_ffi.dylib') if $^O eq 'darwin';
  return ('libantech_kdf.so', 'libantech_kdf_ffi.so');
}

sub find_library {
  my $env = $ENV{ANTECH_KDF_LIB} // '';
  return $env if length $env && -f $env;
  my $root = _repo_root();
  my @dirs = (
    (length $env ? $env : ()),
    File::Spec->catdir($root, 'sdk', 'native'),
    File::Spec->catdir($root, 'target', 'release'),
    File::Spec->catdir($root, 'target', 'debug'),
    File::Spec->catdir(dirname(__FILE__), '..', 'native'),
  );
  for my $d (@dirs) {
    next unless defined $d && length $d;
    for my $n (_library_names()) {
      my $p = File::Spec->catfile($d, $n);
      return $p if -f $p;
    }
  }
  die "native library not found; run sdk/scripts/build-native.(sh|ps1) or set ANTECH_KDF_LIB\n";
}

sub _ffi {
  return $ffi if $ffi;
  $lib_path = find_library();
  $ffi = FFI::Platypus->new(api => 2);
  $ffi->lib($lib_path);
  $ffi->type('record(Antech::Kdf::Config)' => 'AntechConfig');
  $ffi->type('record(Antech::Kdf::RehashPolicy)' => 'AntechRehashPolicy');
  $ffi->attach(antech_version => [] => 'string');
  $ffi->attach(antech_free => ['opaque'] => 'void');
  $ffi->attach(antech_config_default => ['AntechConfig*'] => 'int');
  $ffi->attach(antech_rehash_policy_default => ['AntechRehashPolicy*'] => 'int');
  $ffi->attach(antech_hash_bytes => ['opaque', 'size_t', 'opaque*'] => 'int');
  $ffi->attach(antech_hash_with_config_bytes => ['opaque', 'size_t', 'AntechConfig*', 'opaque*'] => 'int');
  $ffi->attach(antech_hash_with_config_and_salt =>
    ['opaque', 'size_t', 'opaque', 'size_t', 'AntechConfig*', 'opaque*'] => 'int');
  $ffi->attach(antech_hash_with_inputs_bytes =>
    ['opaque', 'size_t', 'AntechConfig*', 'opaque', 'size_t', 'opaque', 'size_t', 'opaque*'] => 'int');
  $ffi->attach(antech_hash_with_inputs_and_salt =>
    ['opaque', 'size_t', 'opaque', 'size_t', 'AntechConfig*', 'opaque', 'size_t', 'opaque', 'size_t', 'opaque*'] => 'int');
  $ffi->attach(antech_verify_bytes => ['opaque', 'size_t', 'string'] => 'int');
  $ffi->attach(antech_verify_with_inputs_bytes =>
    ['opaque', 'size_t', 'string', 'opaque', 'size_t', 'opaque', 'size_t'] => 'int');
  $ffi->attach(antech_needs_rehash => ['string', 'int*'] => 'int');
  $ffi->attach(antech_needs_rehash_with_policy => ['string', 'AntechRehashPolicy*', 'int*'] => 'int');
  return $ffi;
}

sub _raise {
  my ($st) = @_;
  return if $st == 0;
  my %msg = (-1 => 'invalid input', -2 => 'invalid hash', -4 => 'invalid config');
  die(($msg{$st} // "internal error ($st)") . "\n");
}

sub _take {
  my ($ptr) = @_;
  die "null string\n" unless defined $ptr && $ptr;
  my $s = $ffi->cast('opaque' => 'string', $ptr);
  antech_free($ptr);
  return $s;
}

# undef = absent; '' = present empty
sub _opt {
  my ($data) = @_;
  return (undef, 0) unless defined $data;
  return (scalar_to_buffer("\0"), 0) if length($data) == 0;  # non-null empty
  return scalar_to_buffer($data);
}

sub _bytes {
  my ($data) = @_;
  $data = '' unless defined $data;
  return scalar_to_buffer($data);
}

package Antech::Kdf::Config {
  use FFI::Platypus::Record;
  record_layout_1(
    uint32 => 'memory_kib',
    uint32 => 'salt_length',
    uint32 => 'block_size',
    uint32 => 'fan_in',
    uint32 => 'graph',
    uint32 => 'output_length',
  );
}

package Antech::Kdf::RehashPolicy {
  use FFI::Platypus::Record;
  record_layout_1(
    uint32 => 'minimum_memory_kib',
    uint32 => 'preferred_memory_kib',
    uint32 => 'preferred_fan_in',
    uint32 => 'preferred_output_length',
    uint32 => 'preferred_secret_required',
    uint32 => 'preferred_associated_data',
  );
}

package Antech::Kdf;

sub version {
  _ffi();
  return antech_version() // $VERSION;
}

sub config_default {
  _ffi();
  my $c = Antech::Kdf::Config->new();
  _raise(antech_config_default($c));
  return $c;
}

sub rehash_policy_default {
  _ffi();
  my $p = Antech::Kdf::RehashPolicy->new();
  _raise(antech_rehash_policy_default($p));
  return $p;
}

sub hash {
  my ($password) = @_;
  _ffi();
  my ($pw, $len) = _bytes($password);
  my $out;
  _raise(antech_hash_bytes($pw, $len, \$out));
  return _take($out);
}

sub hash_with_config {
  my ($password, $config) = @_;
  _ffi();
  my ($pw, $len) = _bytes($password);
  my $out;
  _raise(antech_hash_with_config_bytes($pw, $len, $config, \$out));
  return _take($out);
}

sub hash_with_config_and_salt {
  my ($password, $salt, $config) = @_;
  _ffi();
  my ($pw, $pw_len) = _bytes($password);
  my ($s, $s_len) = _bytes($salt);
  my $out;
  _raise(antech_hash_with_config_and_salt($pw, $pw_len, $s, $s_len, $config, \$out));
  return _take($out);
}

sub hash_with_inputs {
  my ($password, $config, $secret, $ad) = @_;
  _ffi();
  my ($pw, $pw_len) = _bytes($password);
  my ($sec, $sec_len) = _opt($secret);
  my ($adp, $ad_len) = _opt($ad);
  my $out;
  _raise(antech_hash_with_inputs_bytes($pw, $pw_len, $config, $sec, $sec_len, $adp, $ad_len, \$out));
  return _take($out);
}

sub hash_with_inputs_and_salt {
  my ($password, $salt, $config, $secret, $ad) = @_;
  _ffi();
  my ($pw, $pw_len) = _bytes($password);
  my ($s, $s_len) = _bytes($salt);
  my ($sec, $sec_len) = _opt($secret);
  my ($adp, $ad_len) = _opt($ad);
  my $out;
  _raise(antech_hash_with_inputs_and_salt(
    $pw, $pw_len, $s, $s_len, $config, $sec, $sec_len, $adp, $ad_len, \$out
  ));
  return _take($out);
}

sub verify {
  my ($password, $encoded) = @_;
  _ffi();
  my ($pw, $len) = _bytes($password);
  my $st = antech_verify_bytes($pw, $len, $encoded);
  return 1 if $st == 0;
  return 0 if $st == 1;
  _raise($st);
}

sub verify_with_inputs {
  my ($password, $encoded, $secret, $ad) = @_;
  _ffi();
  my ($pw, $len) = _bytes($password);
  my ($sec, $sec_len) = _opt($secret);
  my ($adp, $ad_len) = _opt($ad);
  my $st = antech_verify_with_inputs_bytes($pw, $len, $encoded, $sec, $sec_len, $adp, $ad_len);
  return 1 if $st == 0;
  return 0 if $st == 1;
  _raise($st);
}

sub needs_rehash {
  my ($encoded) = @_;
  _ffi();
  my $out = 0;
  _raise(antech_needs_rehash($encoded, \$out));
  return $out != 0;
}

sub needs_rehash_with_policy {
  my ($encoded, $policy) = @_;
  _ffi();
  my $out = 0;
  _raise(antech_needs_rehash_with_policy($encoded, $policy, \$out));
  return $out != 0;
}

1;
