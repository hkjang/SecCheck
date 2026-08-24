// Package vault stores evidence blobs encrypted at rest under per-user data
// keys. Blobs are written and read as chunked streams so neither an upload nor
// a download has to fit in memory; blobs written before the chunked format
// existed are single-shot base64 and still open.
package vault

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hkjang/SecCheck/internal/cryptox"
	"github.com/hkjang/SecCheck/internal/store"
)

type Vault struct {
	Dir   string
	Box   *cryptox.Box
	Store *store.Store
}

func New(dir string, box *cryptox.Box, s *store.Store) *Vault {
	return &Vault{Dir: dir, Box: box, Store: s}
}

// AAD binds a blob to the evidence record and version it belongs to.
func AAD(evidenceID string, version int) []byte {
	return []byte(fmt.Sprintf("evidence:%s:%d", evidenceID, version))
}

func (v *Vault) Path(name string) string {
	if len(name) < 2 {
		return filepath.Join(v.Dir, "evidence", "invalid")
	}
	return filepath.Join(v.Dir, "evidence", name[:2], filepath.Base(name))
}

// Write encrypts src chunk by chunk straight to disk and returns the plaintext
// size and its SHA-256.
func (v *Vault) Write(name string, key, aad []byte, src io.Reader) (int64, string, error) {
	dir := filepath.Join(v.Dir, "evidence", name[:2])
	if err := os.MkdirAll(dir, 0700); err != nil {
		return 0, "", err
	}
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 0, "", err
	}
	buffered := bufio.NewWriterSize(f, 1<<20)
	size, digest, err := cryptox.SealStream(buffered, src, key, aad)
	if err == nil {
		err = buffered.Flush()
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return 0, "", err
	}
	return size, hex.EncodeToString(digest), nil
}

// Read decrypts a stored blob into dst and returns the plaintext size and its
// SHA-256.
func (v *Vault) Read(dst io.Writer, name string, key, aad []byte) (int64, string, error) {
	f, err := os.Open(v.Path(name))
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	header := make([]byte, cryptox.StreamHeaderSize())
	n, err := io.ReadFull(f, header)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return 0, "", err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return 0, "", err
	}
	if cryptox.IsStream(header[:n]) {
		size, digest, streamErr := cryptox.OpenStream(dst, bufio.NewReaderSize(f, 1<<20), key, aad)
		return size, hex.EncodeToString(digest), streamErr
	}
	encoded, err := io.ReadAll(f)
	if err != nil {
		return 0, "", err
	}
	// Legacy blobs are sealed in one shot with the owner's data key.
	plain, err := decryptWithKey(key, string(encoded), aad)
	if err != nil {
		return 0, "", err
	}
	digest := sha256.Sum256(plain)
	written, err := dst.Write(plain)
	return int64(written), hex.EncodeToString(digest[:]), err
}

// VerifyBlob reads one stored blob back and reports why it does not match what
// the database says, or "" when it does. The command line tool and the hourly
// sweep ask the same question, and asking it two different ways is how the two
// answers start to disagree.
func (v *Vault) VerifyBlob(ctx context.Context, evidenceID, stored, owner string, keyVersion, version int, size int64, digest string) string {
	key, err := v.UserKey(ctx, owner, keyVersion)
	if err != nil {
		return "encryption key unavailable: " + err.Error()
	}
	readSize, readDigest, err := v.Read(io.Discard, stored, key, AAD(evidenceID, version))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "encrypted file is missing from the evidence volume"
		}
		return err.Error()
	}
	if readSize != size {
		return fmt.Sprintf("size mismatch: stored %d bytes, recorded %d", readSize, size)
	}
	if !strings.EqualFold(readDigest, digest) {
		return "SHA-256 mismatch between the file and the database"
	}
	return ""
}

// EnsureUserKey creates the caller's first data key if they do not have one.
func (v *Vault) EnsureUserKey(ctx context.Context, userID string) error {
	var n int
	if err := v.Store.Pool.QueryRow(ctx, `SELECT count(*) FROM user_data_keys WHERE user_id=$1`, userID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	key, err := cryptox.RandomBytes(32)
	if err != nil {
		return err
	}
	encrypted, err := v.Box.Encrypt(key, []byte("user-key:"+userID+":1"))
	if err != nil {
		return err
	}
	_, err = v.Store.Pool.Exec(ctx, `INSERT INTO user_data_keys(user_id,version,encrypted_key) VALUES($1,1,$2) ON CONFLICT DO NOTHING`, userID, encrypted)
	return err
}

// Storage describes the volume evidence is written to. An appliance that runs
// for years offline fills its disk eventually, and the first sign used to be
// an upload failing.
type Storage struct {
	Path       string `json:"path"`
	Writable   bool   `json:"writable"`
	FreeBytes  uint64 `json:"free_bytes"`
	TotalBytes uint64 `json:"total_bytes"`
	Detail     string `json:"detail,omitempty"`
}

// Space probes the evidence volume: whether it can be written to at all, and
// how much room is left. The write probe is the honest test -- a read-only
// mount and a full disk both report plenty of inodes.
func (v *Vault) Space() Storage {
	dir := filepath.Join(v.Dir, "evidence")
	out := Storage{Path: dir}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		out.Detail = err.Error()
		return out
	}
	probe, err := os.CreateTemp(dir, ".writable-*")
	if err != nil {
		out.Detail = err.Error()
	} else {
		out.Writable = true
		name := probe.Name()
		_ = probe.Close()
		_ = os.Remove(name)
	}
	free, total, err := diskSpace(dir)
	if err != nil {
		if out.Detail == "" {
			out.Detail = err.Error()
		}
		return out
	}
	out.FreeBytes, out.TotalBytes = free, total
	return out
}

// VerifyMasterKey proves that ENCRYPTION_KEY is the one this database was
// written with, before the service starts answering requests.
//
// Nothing used to check. Starting with the wrong key -- a restore into another
// environment, a copy-paste error, a secret rotated in the deployment but not
// in the vault -- came up healthy: the database pings, /ready is green, people
// sign in. The failure showed up later and elsewhere, as evidence that would
// not download and encrypted settings that silently read as unset, which is a
// long way from the mistake that caused it. A key that cannot unwrap what is
// already stored is not a service that should be serving.
//
// A database with nothing wrapped in it yet is a first start, and there is
// nothing to disagree with.
func (v *Vault) VerifyMasterKey(ctx context.Context) error {
	var userID, encrypted string
	var version int
	err := v.Store.Pool.QueryRow(ctx, `SELECT user_id,version,encrypted_key FROM user_data_keys ORDER BY user_id,version LIMIT 1`).Scan(&userID, &version, &encrypted)
	if err != nil {
		// No wrapped key at all: a fresh installation.
		return nil
	}
	if _, err = v.Box.Decrypt(encrypted, []byte(fmt.Sprintf("user-key:%s:%d", userID, version))); err != nil {
		return fmt.Errorf("ENCRYPTION_KEY does not match this database: the stored data keys cannot be unwrapped. "+
			"Start with the key this installation was created with -- a different one leaves every evidence file unreadable (%w)", err)
	}
	return nil
}

func (v *Vault) ActiveUserKey(ctx context.Context, userID string) ([]byte, int, error) {
	if err := v.EnsureUserKey(ctx, userID); err != nil {
		return nil, 0, err
	}
	var encrypted string
	var version int
	err := v.Store.Pool.QueryRow(ctx, `SELECT encrypted_key,version FROM user_data_keys WHERE user_id=$1 AND active ORDER BY version DESC LIMIT 1`, userID).Scan(&encrypted, &version)
	if err != nil {
		return nil, 0, err
	}
	plain, err := v.Box.Decrypt(encrypted, []byte(fmt.Sprintf("user-key:%s:%d", userID, version)))
	return plain, version, err
}

func (v *Vault) UserKey(ctx context.Context, userID string, version int) ([]byte, error) {
	var encrypted string
	err := v.Store.Pool.QueryRow(ctx, `SELECT encrypted_key FROM user_data_keys WHERE user_id=$1 AND version=$2`, userID, version).Scan(&encrypted)
	if err != nil {
		return nil, err
	}
	return v.Box.Decrypt(encrypted, []byte(fmt.Sprintf("user-key:%s:%d", userID, version)))
}

func decryptWithKey(key []byte, encoded string, aad []byte) ([]byte, error) {
	box, err := cryptox.New(key)
	if err != nil {
		return nil, err
	}
	return box.Decrypt(encoded, aad)
}
