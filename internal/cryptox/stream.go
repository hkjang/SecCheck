package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Evidence used to be encrypted in one shot and stored base64-encoded, which
// held the whole file in memory three times over and cost 33% extra disk. The
// chunked format below streams instead:
//
//	"SCE1" | uint32 chunk size | repeated { nonce(12) | GCM(chunk) }
//
// Every chunk is sealed with its own random nonce, and the additional data
// carries the caller's context plus the chunk index and a final-chunk marker,
// so a truncated, reordered or spliced file fails to open.
const (
	streamMagic     = "SCE1"
	StreamChunkSize = 1 << 20
	maxChunkSize    = 8 << 20
	headerSize      = len(streamMagic) + 4
)

// IsStream reports whether a stored blob uses the chunked format. Files
// written before it exists start with base64 text and take the legacy path.
func IsStream(prefix []byte) bool {
	return len(prefix) >= len(streamMagic) && string(prefix[:len(streamMagic)]) == streamMagic
}

// StreamHeaderSize is how many bytes IsStream needs.
func StreamHeaderSize() int { return len(streamMagic) }

// SealStream encrypts src into dst and returns the plaintext length and its
// SHA-256, so the caller never needs the bytes in memory to record them.
func SealStream(dst io.Writer, src io.Reader, key, additional []byte) (int64, []byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return 0, nil, err
	}
	header := make([]byte, headerSize)
	copy(header, streamMagic)
	binary.BigEndian.PutUint32(header[len(streamMagic):], uint32(StreamChunkSize))
	if _, err = dst.Write(header); err != nil {
		return 0, nil, err
	}

	digest := sha256.New()
	plain := make([]byte, StreamChunkSize)
	sealed := make([]byte, 0, gcm.NonceSize()+StreamChunkSize+gcm.Overhead())
	var total int64
	var index uint64
	for {
		n, readErr := io.ReadFull(src, plain)
		final := readErr == io.EOF || readErr == io.ErrUnexpectedEOF
		if readErr != nil && !final {
			return 0, nil, readErr
		}
		// A stream whose length is an exact multiple of the chunk size still
		// needs a final marker, so an empty last chunk is written on purpose.
		if n == 0 && index > 0 && final {
			if err = writeChunk(dst, gcm, sealed, nil, additional, index, true); err != nil {
				return 0, nil, err
			}
			break
		}
		digest.Write(plain[:n])
		total += int64(n)
		if err = writeChunk(dst, gcm, sealed, plain[:n], additional, index, final); err != nil {
			return 0, nil, err
		}
		index++
		if final {
			break
		}
	}
	return total, digest.Sum(nil), nil
}

// OpenStream decrypts src into dst, returning the plaintext length and its
// SHA-256. Authentication failures stop the copy immediately.
func OpenStream(dst io.Writer, src io.Reader, key, additional []byte) (int64, []byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return 0, nil, err
	}
	header := make([]byte, headerSize)
	if _, err = io.ReadFull(src, header); err != nil {
		return 0, nil, errors.New("invalid encrypted stream header")
	}
	if !IsStream(header) {
		return 0, nil, errors.New("not a SecCheck encrypted stream")
	}
	chunkSize := int(binary.BigEndian.Uint32(header[len(streamMagic):]))
	if chunkSize <= 0 || chunkSize > maxChunkSize {
		return 0, nil, fmt.Errorf("unsupported chunk size %d", chunkSize)
	}
	buf := make([]byte, gcm.NonceSize()+chunkSize+gcm.Overhead())
	digest := sha256.New()
	var total int64
	var index uint64
	for {
		n, readErr := io.ReadFull(src, buf)
		if readErr == io.EOF {
			return 0, nil, errors.New("encrypted stream ended before its final chunk")
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return 0, nil, readErr
		}
		if n < gcm.NonceSize() {
			return 0, nil, errors.New("truncated encrypted chunk")
		}
		final := readErr == io.ErrUnexpectedEOF
		plain, openErr := gcm.Open(nil, buf[:gcm.NonceSize()], buf[gcm.NonceSize():n], chunkAAD(additional, index, final))
		if openErr != nil {
			return 0, nil, errors.New("encrypted stream failed authentication")
		}
		digest.Write(plain)
		total += int64(len(plain))
		if len(plain) > 0 {
			if _, err = dst.Write(plain); err != nil {
				return 0, nil, err
			}
		}
		if final {
			return total, digest.Sum(nil), nil
		}
		index++
	}
}

func writeChunk(dst io.Writer, gcm cipher.AEAD, scratch, plain, additional []byte, index uint64, final bool) error {
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	out := append(scratch[:0], nonce...)
	out = gcm.Seal(out, nonce, plain, chunkAAD(additional, index, final))
	_, err := dst.Write(out)
	return err
}

// chunkAAD binds a chunk to its position in the file so that chunks cannot be
// dropped, duplicated or swapped between files.
func chunkAAD(additional []byte, index uint64, final bool) []byte {
	aad := make([]byte, 0, len(additional)+9)
	aad = append(aad, additional...)
	aad = binary.BigEndian.AppendUint64(aad, index)
	if final {
		return append(aad, 1)
	}
	return append(aad, 0)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("stream key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
