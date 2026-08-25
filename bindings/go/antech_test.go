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

type vectorsFile struct {
	Cases []struct {
		ID          string `json:"id"`
		PasswordHex string `json:"password_hex"`
		SaltHex     string `json:"salt_hex"`
		DigestHex   string `json:"digest_hex"`
		Config      struct {
			MemoryKiB    uint32 `json:"memory_kib"`
			SaltLength   uint32 `json:"salt_length"`
			BlockSize    uint32 `json:"block_size"`
			FanIn        uint32 `json:"fan_in"`
			Graph        uint32 `json:"graph"`
			OutputLength uint32 `json:"output_length"`
		} `json:"config"`
	} `json:"cases"`
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
		pw, _ := hex.DecodeString(c.PasswordHex)
		salt, _ := hex.DecodeString(c.SaltHex)
		cfg := Config{
			MemoryKiB: c.Config.MemoryKiB, SaltLength: c.Config.SaltLength,
			BlockSize: c.Config.BlockSize, FanIn: c.Config.FanIn,
			Graph: c.Config.Graph, OutputLength: c.Config.OutputLength,
		}
		enc, err := HashWithConfigAndSalt(pw, salt, cfg)
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		idx := strings.LastIndex(enc, "$")
		digest := enc[idx+1:]
		if digest != c.DigestHex {
			t.Fatalf("%s digest want %s got %s", c.ID, c.DigestHex, digest)
		}
		ok, err := Verify(pw, enc)
		if err != nil || !ok {
			t.Fatalf("%s verify", c.ID)
		}
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
