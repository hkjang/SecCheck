package cryptox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func roundTrip(t *testing.T, size int) {
	t.Helper()
	key, _ := RandomBytes(32)
	plain := make([]byte, size)
	for i := range plain {
		plain[i] = byte(i * 7)
	}
	aad := []byte("evidence:abc:1")
	var sealed bytes.Buffer
	n, digest, err := SealStream(&sealed, bytes.NewReader(plain), key, aad)
	if err != nil {
		t.Fatalf("seal %d bytes: %v", size, err)
	}
	if n != int64(size) {
		t.Fatalf("sealed length = %d, want %d", n, size)
	}
	want := sha256.Sum256(plain)
	if hex.EncodeToString(digest) != hex.EncodeToString(want[:]) {
		t.Fatalf("seal reported the wrong digest for %d bytes", size)
	}
	if !IsStream(sealed.Bytes()) {
		t.Fatal("sealed output is not recognised as a stream")
	}
	var opened bytes.Buffer
	m, digest2, err := OpenStream(&opened, bytes.NewReader(sealed.Bytes()), key, aad)
	if err != nil {
		t.Fatalf("open %d bytes: %v", size, err)
	}
	if m != int64(size) || !bytes.Equal(opened.Bytes(), plain) {
		t.Fatalf("round trip lost data at %d bytes (got %d)", size, m)
	}
	if hex.EncodeToString(digest2) != hex.EncodeToString(want[:]) {
		t.Fatal("open reported the wrong digest")
	}
}

func TestStreamRoundTripAcrossChunkBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, 4096, StreamChunkSize - 1, StreamChunkSize, StreamChunkSize + 1, 2*StreamChunkSize + 17} {
		roundTrip(t, size)
	}
}

func sealSample(t *testing.T, key, aad []byte, size int) []byte {
	t.Helper()
	var out bytes.Buffer
	if _, _, err := SealStream(&out, bytes.NewReader(bytes.Repeat([]byte{9}, size)), key, aad); err != nil {
		t.Fatalf("seal: %v", err)
	}
	return out.Bytes()
}

func TestStreamRejectsTamperingTruncationAndWrongContext(t *testing.T) {
	key, _ := RandomBytes(32)
	aad := []byte("evidence:abc:1")
	sealed := sealSample(t, key, aad, 3*StreamChunkSize)

	cases := map[string][]byte{
		"truncated at a chunk boundary": sealed[:headerSize+2*(12+StreamChunkSize+16)],
		"truncated mid-chunk":           sealed[:len(sealed)-8],
		"flipped ciphertext bit":        flip(sealed, headerSize+64),
		"flipped header bit":            flip(sealed, 1),
	}
	for name, corrupted := range cases {
		if _, _, err := OpenStream(&bytes.Buffer{}, bytes.NewReader(corrupted), key, aad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, _, err := OpenStream(&bytes.Buffer{}, bytes.NewReader(sealed), key, []byte("evidence:abc:2")); err == nil {
		t.Error("a stream opened under the wrong additional data")
	}
	other, _ := RandomBytes(32)
	if _, _, err := OpenStream(&bytes.Buffer{}, bytes.NewReader(sealed), other, aad); err == nil {
		t.Error("a stream opened under the wrong key")
	}
}

// Swapping two chunks must fail even though both are individually valid.
func TestStreamRejectsReorderedChunks(t *testing.T) {
	key, _ := RandomBytes(32)
	aad := []byte("evidence:abc:1")
	sealed := sealSample(t, key, aad, 3*StreamChunkSize)
	chunk := 12 + StreamChunkSize + 16
	reordered := append([]byte{}, sealed[:headerSize]...)
	reordered = append(reordered, sealed[headerSize+chunk:headerSize+2*chunk]...)
	reordered = append(reordered, sealed[headerSize:headerSize+chunk]...)
	reordered = append(reordered, sealed[headerSize+2*chunk:]...)
	if _, _, err := OpenStream(&bytes.Buffer{}, bytes.NewReader(reordered), key, aad); err == nil {
		t.Error("reordered chunks were accepted")
	}
}

func TestIsStreamRejectsLegacyBase64Blobs(t *testing.T) {
	box, err := New(mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := box.Encrypt([]byte("old evidence"), []byte("evidence:abc:1"))
	if err != nil {
		t.Fatal(err)
	}
	if IsStream([]byte(legacy)) {
		t.Fatal("a legacy base64 blob was mistaken for a chunked stream")
	}
}

func mustKey(t *testing.T) []byte {
	t.Helper()
	key, err := RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func flip(in []byte, at int) []byte {
	out := append([]byte{}, in...)
	out[at] ^= 0x01
	return out
}
