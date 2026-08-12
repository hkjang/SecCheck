package cryptox

import (
	"bytes"
	"testing"
)

func TestBoxRoundTripAndAAD(t *testing.T) {
	box, err := New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := box.Encrypt([]byte("민감한 증적"), []byte("evidence:1"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := box.Decrypt(ciphertext, []byte("evidence:1"))
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "민감한 증적" {
		t.Fatalf("got %q", plain)
	}
	if _, err = box.Decrypt(ciphertext, []byte("evidence:2")); err == nil {
		t.Fatal("different AAD must fail authentication")
	}
}
