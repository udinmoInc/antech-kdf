package main

import (
	"fmt"

	antech "github.com/udinmoInc/antech-kdf/bindings/go"
)

func main() {
	h, err := antech.Hash([]byte("correct_horse_battery_staple"))
	if err != nil {
		panic(err)
	}
	ok, _ := antech.Verify([]byte("correct_horse_battery_staple"), h)
	fmt.Println(h, ok)

	cfg := antech.DefaultConfig()
	cfg.MemoryKiB = 1024
	custom, _ := antech.HashWithConfig([]byte("pw"), cfg)
	need, _ := antech.NeedsRehash(custom)
	pol := antech.DefaultRehashPolicy()
	pol.PreferredMemoryKiB = 32768
	needPol, _ := antech.NeedsRehashWithPolicy(custom, pol)
	fmt.Println("needs_rehash", need, "policy", needPol)
}
