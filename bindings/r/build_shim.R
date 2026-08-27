#!/usr/bin/env Rscript
# Build the .Call shim against the prebuilt antech native library.

args <- commandArgs(trailingOnly = FALSE)
file_arg <- grep("^--file=", args, value = TRUE)
script <- if (length(file_arg)) sub("^--file=", "", file_arg) else "bindings/r/build_shim.R"
root <- normalizePath(file.path(dirname(script), "..", ".."), winslash = "/", mustWork = TRUE)
src <- file.path(root, "bindings", "r", "src", "antech_wrap.c")
inc <- file.path(root, "bindings", "c")
libdir <- file.path(root, "sdk", "native")
if (!dir.exists(libdir)) libdir <- file.path(root, "target", "release")

libname <- if (.Platform$OS.type == "windows") "antech_kdf" else "antech_kdf"
# Prefer ffi crate artifact name if present
candidates <- list.files(libdir, pattern = "antech_kdf", full.names = TRUE)
if (!length(candidates)) stop("native library missing under ", libdir)

Sys.setenv(PKG_CPPFLAGS = paste0("-I", shQuote(inc)))
# Link directory
link_flags <- paste0("-L", shQuote(libdir), " -l", libname)
# On Windows MSVC/MinGW naming differs; pass full path when needed
dll <- candidates[1]
if (.Platform$OS.type == "windows") {
  Sys.setenv(PKG_LIBS = shQuote(dll))
} else {
  Sys.setenv(PKG_LIBS = link_flags)
}

old <- setwd(file.path(root, "bindings", "r", "src"))
on.exit(setwd(old), add = TRUE)
status <- system2("R", c("CMD", "SHLIB", "antech_wrap.c"))
if (!identical(status, 0L)) quit(status = status)
message("built antech_wrap in ", getwd())
