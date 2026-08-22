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

// The format claims a chunk cannot be moved between files. Two pieces of
// evidence belonging to the same person share a key, so only the additional
// data -- which names the evidence and its version -- stands between them.
func TestStreamRejectsAChunkSplicedFromAnotherFile(t *testing.T) {
	key, _ := RandomBytes(32)
	first := sealSample(t, key, []byte("evidence:aaa:1"), 3*StreamChunkSize)
	second := sealSample(t, key, []byte("evidence:bbb:1"), 3*StreamChunkSize)
	chunk := 12 + StreamChunkSize + 16

	spliced := append([]byte{}, first[:headerSize+chunk]...)
	spliced = append(spliced, second[headerSize+chunk:headerSize+2*chunk]...)
	spliced = append(spliced, first[headerSize+2*chunk:]...)
	if _, _, err := OpenStream(&bytes.Buffer{}, bytes.NewReader(spliced), key, []byte("evidence:aaa:1")); err == nil {
		t.Error("a chunk taken from another file under the same key was accepted")
	}
}

// A chunk repeated in place lands at an index its additional data does not
// name, so it has to fail even though it is a chunk of this very file.
func TestStreamRejectsADuplicatedChunk(t *testing.T) {
	key, _ := RandomBytes(32)
	aad := []byte("evidence:abc:1")
	sealed := sealSample(t, key, aad, 3*StreamChunkSize)
	chunk := 12 + StreamChunkSize + 16

	duplicated := append([]byte{}, sealed[:headerSize+chunk]...)
	duplicated = append(duplicated, sealed[headerSize:headerSize+chunk]...)
	duplicated = append(duplicated, sealed[headerSize+chunk:]...)
	if _, _, err := OpenStream(&bytes.Buffer{}, bytes.NewReader(duplicated), key, aad); err == nil {
		t.Error("a duplicated chunk was accepted")
	}
}

// A file whose final chunk is followed by more bytes is not the file that was
// written, and the reader used to stop at the final marker and ignore them.
func TestStreamRejectsDataAfterTheFinalChunk(t *testing.T) {
	key, _ := RandomBytes(32)
	aad := []byte("evidence:abc:1")
	sealed := sealSample(t, key, aad, StreamChunkSize+1024)
	padded := append(append([]byte{}, sealed...), []byte("추가로 붙인 바이트")...)
	if _, _, err := OpenStream(&bytes.Buffer{}, bytes.NewReader(padded), key, aad); err == nil {
		t.Error("bytes after the final chunk were ignored")
	}
}
