# Antech KDF — R

Thin `.Call` wrapper over `libantech_kdf`. Build the native library, then the R shim:

```bash
./sdk/scripts/build-native.sh   # or build-native.ps1 on Windows
Rscript bindings/r/build_shim.R
Rscript bindings/r/examples/basic.R
```

```r
source("bindings/r/R/antech.R")
stored <- antech_hash("correct_horse_battery_staple")
stopifnot(antech_verify("correct_horse_battery_staple", stored))
```

Requires an R toolchain able to compile C (`R CMD SHLIB`) and link the Antech cdylib.
