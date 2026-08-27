# Antech KDF — Ruby

Thin [`ffi`](https://github.com/ffi/ffi) wrapper. Build the native library first:

```bash
./sdk/scripts/build-native.sh
gem install ffi
ruby -Ibindings/ruby/lib bindings/ruby/examples/basic.rb
```

```ruby
require "antech_kdf"

stored = Antech.hash("correct_horse_battery_staple")
raise unless Antech.verify("correct_horse_battery_staple", stored)
```

Optional secret / associated data: `nil` = absent; `""` = present-but-empty.
