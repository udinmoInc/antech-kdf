import '../lib/antech_kdf.dart';

void main() {
  final stored = hash('correct_horse_battery_staple');
  assert(verify('correct_horse_battery_staple', stored));

  final cfg = Config.defaults()..memoryKib = 1024;
  final custom = hashWithConfig('pw', cfg);
  print('needs_rehash ${needsRehash(custom)}');
  print(stored);
}
