# Antech KDF — Dart

Thin [`dart:ffi`](https://dart.dev/guides/libraries/c-interop) wrapper. Build the native library first:

```bash
./sdk/scripts/build-native.sh
cd bindings/dart && dart pub get
dart run examples/basic.dart
```

```dart
import 'package:antech_kdf/antech_kdf.dart';

final stored = hash('correct_horse_battery_staple');
assert(verify('correct_horse_battery_staple', stored));
```

Optional secret / associated data: `null` = absent; empty `Uint8List` = present-but-empty.
