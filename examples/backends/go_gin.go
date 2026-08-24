// Backend Integration Example: Go + Gin
// Demonstrates strictly where HashPassword() and VerifyPassword() are invoked.

package main

import "github.com/antech-kdf/antech-kdf-go"

func RegisterUser(password string) (string, error) {
    return antech.HashPassword(password)
}

func LoginUser(password string, storedHash string) (bool, error) {
    return antech.VerifyPassword(password, storedHash)
}
