// Backend sketch: register/login with the Go binding (CGO).

package main

import antech "github.com/udinmo/antech-kdf/bindings/go"

func RegisterUser(password string) (string, error) {
	return antech.Hash([]byte(password))
}

func LoginUser(password, storedHash string) (bool, error) {
	return antech.Verify([]byte(password), storedHash)
}
