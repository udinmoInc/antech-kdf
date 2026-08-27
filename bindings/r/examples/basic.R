#!/usr/bin/env Rscript
args <- commandArgs(trailingOnly = FALSE)
file_arg <- grep("^--file=", args, value = TRUE)
ex <- if (length(file_arg)) dirname(sub("^--file=", "", file_arg[[1]])) else getwd()
source(file.path(ex, "..", "R", "antech.R"))

stored <- antech_hash("correct_horse_battery_staple")
stopifnot(isTRUE(antech_verify("correct_horse_battery_staple", stored)))
cfg <- antech_config_default()
cfg$memory_kib <- 1024L
custom <- antech_hash_with_config("pw", cfg)
message("needs_rehash ", antech_needs_rehash(custom))
cat(stored, "\n", sep = "")
