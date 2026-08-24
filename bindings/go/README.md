# Antech KDF Go Binding

Uses cgo calling `antech-kdf-ffi`.

```go
package main

import "github.com/antech-kdf/antech-kdf-go"

func main() {
    hash, _ := antech.HashPassword("hello")
    valid, _ := antech.VerifyPassword("hello", hash)
}
```
