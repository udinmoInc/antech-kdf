// Package antech wraps the Antech KDF C ABI (CGO; see README for linking).
package antech

/*
#cgo CFLAGS: -I${SRCDIR}/../c
#cgo LDFLAGS: -L${SRCDIR}/../../sdk/native -L${SRCDIR}/../../target/release
#cgo linux LDFLAGS: -lantech_kdf_ffi -ldl -lm -lpthread
#cgo darwin LDFLAGS: -lantech_kdf_ffi
#cgo windows LDFLAGS: -lantech_kdf_ffi
#include "antech_kdf.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

const Version = "0.1.0"

var (
	ErrInvalidInput        = errors.New("antech: invalid input")
	ErrInvalidHash         = errors.New("antech: invalid hash")
	ErrInternal            = errors.New("antech: internal error")
	ErrInvalidConfig       = errors.New("antech: invalid config")
	ErrVerificationFailed  = errors.New("antech: verification failed")
)

func mapStatus(st C.AntechStatus) error {
	switch st {
	case C.ANTECH_OK:
		return nil
	case C.ANTECH_VERIFICATION_FAILED:
		return ErrVerificationFailed
	case C.ANTECH_INVALID_INPUT:
		return ErrInvalidInput
	case C.ANTECH_INVALID_HASH:
		return ErrInvalidHash
	case C.ANTECH_INVALID_CONFIG:
		return ErrInvalidConfig
	default:
		return ErrInternal
	}
}

// Config mirrors AntechConfig.
type Config struct {
	MemoryKiB    uint32
	SaltLength   uint32
	BlockSize    uint32
	FanIn        uint32
	Graph        uint32
	OutputLength uint32
}

func DefaultConfig() Config {
	var c C.AntechConfig
	if err := mapStatus(C.antech_config_default(&c)); err != nil {
		panic(err)
	}
	return Config{
		MemoryKiB:    uint32(c.memory_kib),
		SaltLength:   uint32(c.salt_length),
		BlockSize:    uint32(c.block_size),
		FanIn:        uint32(c.fan_in),
		Graph:        uint32(c.graph),
		OutputLength: uint32(c.output_length),
	}
}

func (c Config) c() C.AntechConfig {
	return C.AntechConfig{
		memory_kib:    C.uint32_t(c.MemoryKiB),
		salt_length:   C.uint32_t(c.SaltLength),
		block_size:    C.uint32_t(c.BlockSize),
		fan_in:        C.uint32_t(c.FanIn),
		graph:         C.uint32_t(c.Graph),
		output_length: C.uint32_t(c.OutputLength),
	}
}

// RehashPolicy mirrors AntechRehashPolicy.
type RehashPolicy struct {
	MinimumMemoryKiB          uint32
	PreferredMemoryKiB        uint32
	PreferredFanIn            uint32
	PreferredOutputLength     uint32
	PreferredSecretRequired   bool
	PreferredAssociatedData   bool
}

func DefaultRehashPolicy() RehashPolicy {
	var p C.AntechRehashPolicy
	if err := mapStatus(C.antech_rehash_policy_default(&p)); err != nil {
		panic(err)
	}
	return RehashPolicy{
		MinimumMemoryKiB:        uint32(p.minimum_memory_kib),
		PreferredMemoryKiB:      uint32(p.preferred_memory_kib),
		PreferredFanIn:          uint32(p.preferred_fan_in),
		PreferredOutputLength:   uint32(p.preferred_output_length),
		PreferredSecretRequired: p.preferred_secret_required != 0,
		PreferredAssociatedData: p.preferred_associated_data != 0,
	}
}

func (p RehashPolicy) c() C.AntechRehashPolicy {
	var sk, ad C.uint32_t
	if p.PreferredSecretRequired {
		sk = 1
	}
	if p.PreferredAssociatedData {
		ad = 1
	}
	return C.AntechRehashPolicy{
		minimum_memory_kib:         C.uint32_t(p.MinimumMemoryKiB),
		preferred_memory_kib:       C.uint32_t(p.PreferredMemoryKiB),
		preferred_fan_in:           C.uint32_t(p.PreferredFanIn),
		preferred_output_length:    C.uint32_t(p.PreferredOutputLength),
		preferred_secret_required:  sk,
		preferred_associated_data:  ad,
	}
}

// DeriveInputs carries optional secret and associated data.
// nil slice = absent; non-nil empty slice = present but empty.
type DeriveInputs struct {
	Secret         []byte
	AssociatedData []byte
}

var emptyScratch byte

func bytePtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func optPtr(b []byte) (*C.uint8_t, C.size_t) {
	if b == nil {
		return nil, 0
	}
	if len(b) == 0 {
		return (*C.uint8_t)(unsafe.Pointer(&emptyScratch)), 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b))
}

func takeString(p *C.char) string {
	s := C.GoString(p)
	C.antech_free(p)
	return s
}

func Hash(password []byte) (string, error) {
	var out *C.char
	st := C.antech_hash_bytes(bytePtr(password), C.size_t(len(password)), &out)
	if err := mapStatus(st); err != nil {
		return "", err
	}
	return takeString(out), nil
}

func HashWithConfig(password []byte, cfg Config) (string, error) {
	c := cfg.c()
	var out *C.char
	st := C.antech_hash_with_config_bytes(bytePtr(password), C.size_t(len(password)), &c, &out)
	if err := mapStatus(st); err != nil {
		return "", err
	}
	return takeString(out), nil
}

func HashWithConfigAndSalt(password, salt []byte, cfg Config) (string, error) {
	c := cfg.c()
	var out *C.char
	st := C.antech_hash_with_config_and_salt(
		bytePtr(password), C.size_t(len(password)),
		bytePtr(salt), C.size_t(len(salt)),
		&c, &out,
	)
	if err := mapStatus(st); err != nil {
		return "", err
	}
	return takeString(out), nil
}

func HashWithInputs(password []byte, cfg Config, inputs DeriveInputs) (string, error) {
	c := cfg.c()
	var out *C.char
	sec, secLen := optPtr(inputs.Secret)
	ad, adLen := optPtr(inputs.AssociatedData)
	st := C.antech_hash_with_inputs_bytes(
		bytePtr(password), C.size_t(len(password)), &c, sec, secLen, ad, adLen, &out,
	)
	if err := mapStatus(st); err != nil {
		return "", err
	}
	return takeString(out), nil
}

func HashWithInputsAndSalt(password, salt []byte, cfg Config, inputs DeriveInputs) (string, error) {
	c := cfg.c()
	var out *C.char
	sec, secLen := optPtr(inputs.Secret)
	ad, adLen := optPtr(inputs.AssociatedData)
	st := C.antech_hash_with_inputs_and_salt(
		bytePtr(password), C.size_t(len(password)),
		bytePtr(salt), C.size_t(len(salt)),
		&c, sec, secLen, ad, adLen, &out,
	)
	if err := mapStatus(st); err != nil {
		return "", err
	}
	return takeString(out), nil
}

func Verify(password []byte, encodedHash string) (bool, error) {
	ch := C.CString(encodedHash)
	defer C.free(unsafe.Pointer(ch))
	st := C.antech_verify_bytes(bytePtr(password), C.size_t(len(password)), ch)
	switch st {
	case C.ANTECH_OK:
		return true, nil
	case C.ANTECH_VERIFICATION_FAILED:
		return false, nil
	default:
		return false, mapStatus(st)
	}
}

func VerifyWithInputs(password []byte, encodedHash string, inputs DeriveInputs) (bool, error) {
	ch := C.CString(encodedHash)
	defer C.free(unsafe.Pointer(ch))
	sec, secLen := optPtr(inputs.Secret)
	ad, adLen := optPtr(inputs.AssociatedData)
	st := C.antech_verify_with_inputs_bytes(
		bytePtr(password), C.size_t(len(password)), ch, sec, secLen, ad, adLen,
	)
	switch st {
	case C.ANTECH_OK:
		return true, nil
	case C.ANTECH_VERIFICATION_FAILED:
		return false, nil
	default:
		return false, mapStatus(st)
	}
}

func NeedsRehash(encodedHash string) (bool, error) {
	ch := C.CString(encodedHash)
	defer C.free(unsafe.Pointer(ch))
	var out C.int
	if err := mapStatus(C.antech_needs_rehash(ch, &out)); err != nil {
		return false, err
	}
	return out != 0, nil
}

func NeedsRehashWithPolicy(encodedHash string, policy RehashPolicy) (bool, error) {
	ch := C.CString(encodedHash)
	defer C.free(unsafe.Pointer(ch))
	p := policy.c()
	var out C.int
	if err := mapStatus(C.antech_needs_rehash_with_policy(ch, &p, &out)); err != nil {
		return false, err
	}
	return out != 0, nil
}

func LibraryVersion() string {
	return C.GoString(C.antech_version())
}

func MustHash(password string) string {
	h, err := Hash([]byte(password))
	if err != nil {
		panic(fmt.Sprintf("hash: %v", err))
	}
	return h
}
