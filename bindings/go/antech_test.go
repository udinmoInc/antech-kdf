package antech

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type vectorCase struct {
	ID                 string  `json:"id"`
	PasswordHex        string  `json:"password_hex"`
	SaltHex            string  `json:"salt_hex"`
	DigestHex          string  `json:"digest_hex"`
	SecretHex          *string `json:"secret_hex"`
	AssociatedDataHex  *string `json:"associated_data_hex"`
	Config             struct {
		MemoryKiB    uint32 `json:"memory_kib"`
		SaltLength   uint32 `json:"salt_length"`
		BlockSize    uint32 `json:"block_size"`
		FanIn        uint32 `json:"fan_in"`
		Graph        uint32 `json:"graph"`
		OutputLength uint32 `json:"output_length"`
	} `json:"config"`
}

type vectorsFile struct {
	Cases []vectorCase `json:"cases"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// omit key = absent; "" = present empty; hex = present bytes
func optHex(t *testing.T, p *string) []byte {
	t.Helper()
	if p == nil {
		return nil
	}
	if *p == "" {
		return []byte{}
	}
	return mustHex(t, *p)
}

func TestConformance(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "sdk", "conformance", "vectors.json"))
	if err != nil {
		t.Skip("vectors missing:", err)
	}
	var doc vectorsFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			pw := mustHex(t, c.PasswordHex)
			salt := mustHex(t, c.SaltHex)
			cfg := Config{
				MemoryKiB:    c.Config.MemoryKiB,
				SaltLength:   c.Config.SaltLength,
				BlockSize:    c.Config.BlockSize,
				FanIn:        c.Config.FanIn,
				Graph:        c.Config.Graph,
				OutputLength: c.Config.OutputLength,
			}
			secret := optHex(t, c.SecretHex)
			ad := optHex(t, c.AssociatedDataHex)
			hasExtras := c.SecretHex != nil || c.AssociatedDataHex != nil

			var enc string
			if hasExtras {
				enc, err = HashWithInputsAndSalt(pw, salt, cfg, DeriveInputs{
					Secret:         secret,
					AssociatedData: ad,
				})
			} else {
				enc, err = HashWithConfigAndSalt(pw, salt, cfg)
			}
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			digest := enc[strings.LastIndex(enc, "$")+1:]
			if digest != c.DigestHex {
				t.Fatalf("digest want %s got %s", c.DigestHex, digest)
			}
			if hasExtras {
				ok, err := VerifyWithInputs(pw, enc, DeriveInputs{
					Secret:         secret,
					AssociatedData: ad,
				})
				if err != nil || !ok {
					t.Fatalf("verify_with_inputs: ok=%v err=%v", ok, err)
				}
			} else {
				ok, err := Verify(pw, enc)
				if err != nil || !ok {
					t.Fatalf("verify: ok=%v err=%v", ok, err)
				}
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	h, err := Hash([]byte("password"))
	if err != nil {
		t.Skip("native lib unavailable:", err)
	}
	ok, err := Verify([]byte("password"), h)
	if err != nil || !ok {
		t.Fatal("verify")
	}
}
