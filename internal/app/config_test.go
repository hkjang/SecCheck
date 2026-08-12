package app

import (
	"encoding/base64"
	"testing"
)

func TestParseEncryptionKey(t *testing.T) {
	raw := "0123456789abcdef0123456789abcdef"
	if key, err := parseEncryptionKey(raw); err != nil || string(key) != raw {
		t.Fatalf("raw key failed: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	if key, err := parseEncryptionKey(encoded); err != nil || string(key) != raw {
		t.Fatalf("base64 key failed: %v", err)
	}
	if _, err := parseEncryptionKey("too-short"); err == nil {
		t.Fatal("short key was accepted")
	}
}
