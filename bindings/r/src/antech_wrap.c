/* Thin .Call wrappers over antech-kdf-ffi. Link with -lantech_kdf (or antech_kdf_ffi). */
#include <R.h>
#include <Rinternals.h>
#include <stdint.h>
#include <string.h>

#include "../../c/antech_kdf.h"

static void raise_status(AntechStatus st) {
  if (st == ANTECH_OK) return;
  if (st == ANTECH_INVALID_INPUT) Rf_error("invalid input");
  if (st == ANTECH_INVALID_HASH) Rf_error("invalid hash");
  if (st == ANTECH_INVALID_CONFIG) Rf_error("invalid config");
  Rf_error("internal error (%d)", (int)st);
}

static SEXP take_string(char* p) {
  if (!p) Rf_error("null string");
  SEXP out = Rf_mkString(p);
  antech_free(p);
  return out;
}

SEXP antech_r_version(void) {
  const char* v = antech_version();
  return Rf_mkString(v ? v : "0.1.0");
}

SEXP antech_r_hash(SEXP password) {
  if (!Rf_isString(password) || Rf_length(password) < 1) Rf_error("password must be a string");
  const char* pw = CHAR(STRING_ELT(password, 0));
  char* out = NULL;
  raise_status(antech_hash_bytes((const uint8_t*)pw, strlen(pw), &out));
  return take_string(out);
}

SEXP antech_r_hash_with_config(SEXP password, SEXP cfg_vec) {
  if (!Rf_isString(password) || Rf_length(password) < 1) Rf_error("password must be a string");
  if (!Rf_isInteger(cfg_vec) || Rf_length(cfg_vec) < 6) Rf_error("config must be integer[6]");
  const int* c = INTEGER(cfg_vec);
  AntechConfig cfg = {
    (uint32_t)c[0], (uint32_t)c[1], (uint32_t)c[2],
    (uint32_t)c[3], (uint32_t)c[4], (uint32_t)c[5]
  };
  const char* pw = CHAR(STRING_ELT(password, 0));
  char* out = NULL;
  raise_status(antech_hash_with_config_bytes((const uint8_t*)pw, strlen(pw), &cfg, &out));
  return take_string(out);
}

SEXP antech_r_verify(SEXP password, SEXP encoded) {
  if (!Rf_isString(password) || Rf_length(password) < 1) Rf_error("password must be a string");
  if (!Rf_isString(encoded) || Rf_length(encoded) < 1) Rf_error("encoded must be a string");
  const char* pw = CHAR(STRING_ELT(password, 0));
  const char* enc = CHAR(STRING_ELT(encoded, 0));
  AntechStatus st = antech_verify_bytes((const uint8_t*)pw, strlen(pw), enc);
  if (st == ANTECH_OK) return Rf_ScalarLogical(1);
  if (st == ANTECH_VERIFICATION_FAILED) return Rf_ScalarLogical(0);
  raise_status(st);
  return R_NilValue;
}

SEXP antech_r_needs_rehash(SEXP encoded) {
  if (!Rf_isString(encoded) || Rf_length(encoded) < 1) Rf_error("encoded must be a string");
  int needs = 0;
  raise_status(antech_needs_rehash(CHAR(STRING_ELT(encoded, 0)), &needs));
  return Rf_ScalarLogical(needs != 0);
}

SEXP antech_r_config_default(void) {
  AntechConfig cfg;
  raise_status(antech_config_default(&cfg));
  SEXP out = PROTECT(Rf_allocVector(INTSXP, 6));
  INTEGER(out)[0] = (int)cfg.memory_kib;
  INTEGER(out)[1] = (int)cfg.salt_length;
  INTEGER(out)[2] = (int)cfg.block_size;
  INTEGER(out)[3] = (int)cfg.fan_in;
  INTEGER(out)[4] = (int)cfg.graph;
  INTEGER(out)[5] = (int)cfg.output_length;
  UNPROTECT(1);
  return out;
}

static const R_CallMethodDef call_methods[] = {
  {"antech_r_version", (DL_FUNC)&antech_r_version, 0},
  {"antech_r_hash", (DL_FUNC)&antech_r_hash, 1},
  {"antech_r_hash_with_config", (DL_FUNC)&antech_r_hash_with_config, 2},
  {"antech_r_verify", (DL_FUNC)&antech_r_verify, 2},
  {"antech_r_needs_rehash", (DL_FUNC)&antech_r_needs_rehash, 1},
  {"antech_r_config_default", (DL_FUNC)&antech_r_config_default, 0},
  {NULL, NULL, 0}
};

void R_init_antech(DllInfo* info) {
  R_registerRoutines(info, NULL, call_methods, NULL, NULL);
  R_useDynamicSymbols(info, FALSE);
}
