# Thin R .Call wrapper; build shim via build_shim.R.
PACKAGE_VERSION <- "0.1.0"

.antech_loaded <- FALSE

.antech_lib_names <- function() {
  if (.Platform$OS.type == "windows") {
    c("antech_kdf.dll", "antech_kdf_ffi.dll")
  } else if (Sys.info()[["sysname"]] == "Darwin") {
    c("libantech_kdf.dylib", "libantech_kdf_ffi.dylib")
  } else {
    c("libantech_kdf.so", "libantech_kdf_ffi.so")
  }
}

find_antech_library <- function() {
  env <- Sys.getenv("ANTECH_KDF_LIB", unset = "")
  if (nzchar(env) && file.exists(env)) return(normalizePath(env, winslash = "/"))
  dirs <- character()
  wd <- getwd()
  for (i in 0:8) {
    dirs <- c(dirs, file.path(wd, "sdk", "native"), file.path(wd, "target", "release"),
              file.path(wd, "target", "debug"))
    wd <- dirname(wd)
  }
  if (nzchar(env) && dir.exists(env)) dirs <- c(env, dirs)
  for (d in unique(dirs)) {
    if (!dir.exists(d)) next
    for (n in .antech_lib_names()) {
      p <- file.path(d, n)
      if (file.exists(p)) return(normalizePath(p, winslash = "/"))
    }
  }
  stop("native library not found; run sdk/scripts/build-native.(sh|ps1) or set ANTECH_KDF_LIB")
}

load_antech <- function(shim_path = NULL) {
  if (isTRUE(.antech_loaded)) return(invisible(TRUE))
  # Ensure the Rust cdylib is on the loader path
  lib <- find_antech_library()
  dyn.load(lib, local = FALSE)
  if (is.null(shim_path)) {
    candidates <- c(
      file.path("bindings", "r", "src", "antech_wrap.so"),
      file.path("bindings", "r", "src", "antech_wrap.dll"),
      file.path("src", "antech_wrap.so"),
      file.path("src", "antech_wrap.dll"),
      system.file("libs", .Platform$r_arch, package = "antech", mustWork = FALSE)
    )
    for (c in candidates) {
      if (nzchar(c) && file.exists(c)) {
        shim_path <- c
        break
      }
    }
  }
  if (is.null(shim_path) || !file.exists(shim_path)) {
    stop("R shim not found. Build with: Rscript bindings/r/build_shim.R")
  }
  dyn.load(shim_path)
  .antech_loaded <<- TRUE
  invisible(TRUE)
}

antech_version <- function() {
  load_antech()
  .Call("antech_r_version")
}

antech_config_default <- function() {
  load_antech()
  v <- .Call("antech_r_config_default")
  list(
    memory_kib = v[1], salt_length = v[2], block_size = v[3],
    fan_in = v[4], graph = v[5], output_length = v[6]
  )
}

antech_hash <- function(password) {
  load_antech()
  .Call("antech_r_hash", as.character(password))
}

antech_hash_with_config <- function(password, config) {
  load_antech()
  cfg <- as.integer(c(
    config$memory_kib, config$salt_length, config$block_size,
    config$fan_in, config$graph, config$output_length
  ))
  .Call("antech_r_hash_with_config", as.character(password), cfg)
}

antech_verify <- function(password, encoded_hash) {
  load_antech()
  .Call("antech_r_verify", as.character(password), as.character(encoded_hash))
}

antech_needs_rehash <- function(encoded_hash) {
  load_antech()
  .Call("antech_r_needs_rehash", as.character(encoded_hash))
}
