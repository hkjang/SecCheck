package vault_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/hkjang/SecCheck/internal/cryptox"
	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/testdb"
	"github.com/hkjang/SecCheck/internal/vault"
)

func newVault(t *testing.T) (*vault.Vault, *store.Store) {
	t.Helper()
	db := testdb.New(t)
	master, err := cryptox.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	box, err := cryptox.New(master)
	if err != nil {
		t.Fatal(err)
	}
	return vault.New(t.TempDir(), box, db), db
}

// Each person's data key is wrapped under additional data naming them and the
// key version. Moving a wrapped key to another person's row -- the shape of a
// database-level attack, or of a careless restore -- must not yield a usable
// key, or one person's evidence becomes readable with another's.
func TestAWrappedKeyCannotBeMovedToAnotherUser(t *testing.T) {
	v, db := newVault(t)
	ctx := context.Background()
	owner := testdb.Bootstrap(t, db, "key-owner")
	other := testdb.Bootstrap(t, db, "key-thief")

	for _, id := range []string{owner, other} {
		if err := v.EnsureUserKey(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	ownerKey, ownerVersion, err := v.ActiveUserKey(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, _, err := v.ActiveUserKey(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ownerKey, otherKey) {
		t.Fatal("two people were given the same data key")
	}

	// Swap the wrapped key rows, exactly as tampering or a bad restore would.
	if _, err := db.Pool.Exec(ctx, `UPDATE user_data_keys AS d SET encrypted_key=(SELECT encrypted_key FROM user_data_keys WHERE user_id=$2 AND version=$3) WHERE d.user_id=$1 AND d.version=$3`, other, owner, ownerVersion); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.ActiveUserKey(ctx, other); err == nil {
		t.Error("a wrapped key moved to another user's row was accepted")
	}
}

// Evidence is bound to its record and version, so the same bytes stored for a
// different evidence id must not open.
func TestStoredEvidenceIsBoundToItsRecord(t *testing.T) {
	v, db := newVault(t)
	ctx := context.Background()
	owner := testdb.Bootstrap(t, db, "vault-owner")
	if err := v.EnsureUserKey(ctx, owner); err != nil {
		t.Fatal(err)
	}
	key, _, err := v.ActiveUserKey(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte("증적 본문 "), 2000)
	size, digest, err := v.Write("blob.enc", key, vault.AAD("ev-1", 1), bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(plain)) || digest == "" {
		t.Fatalf("write reported %d bytes and digest %q", size, digest)
	}

	var out bytes.Buffer
	if _, readDigest, err := v.Read(&out, "blob.enc", key, vault.AAD("ev-1", 1)); err != nil {
		t.Fatalf("reading back what was written: %v", err)
	} else if readDigest != digest || !bytes.Equal(out.Bytes(), plain) {
		t.Error("the round trip changed the file")
	}
	for _, wrong := range [][]byte{vault.AAD("ev-2", 1), vault.AAD("ev-1", 2)} {
		if _, _, err := v.Read(&bytes.Buffer{}, "blob.enc", key, wrong); err == nil {
			t.Errorf("the blob opened as %q", wrong)
		}
	}
	stranger, _ := cryptox.RandomBytes(32)
	if _, _, err := v.Read(&bytes.Buffer{}, "blob.enc", stranger, vault.AAD("ev-1", 1)); err == nil {
		t.Error("the blob opened under a key that never wrote it")
	}
}

// Starting with the wrong ENCRYPTION_KEY used to look like a healthy service:
// the database answers, sign-in works, and the mistake only surfaces later as
// evidence that will not download.
func TestTheMasterKeyIsCheckedAgainstWhatIsStored(t *testing.T) {
	original, db := newVault(t)
	ctx := context.Background()

	// Nothing wrapped yet: a first start has nothing to disagree with.
	if err := original.VerifyMasterKey(ctx); err != nil {
		t.Errorf("an empty installation was rejected: %v", err)
	}
	userID := testdb.Bootstrap(t, db, "key-owner")
	if err := original.EnsureUserKey(ctx, userID); err != nil {
		t.Fatal(err)
	}
	if err := original.VerifyMasterKey(ctx); err != nil {
		t.Errorf("the key that wrote the data was rejected: %v", err)
	}

	other, err := cryptox.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	box, err := cryptox.New(other)
	if err != nil {
		t.Fatal(err)
	}
	stranger := vault.New(t.TempDir(), box, db)
	err = stranger.VerifyMasterKey(ctx)
	if err == nil {
		t.Fatal("a database written with another key was accepted")
	}
	if !strings.Contains(err.Error(), "ENCRYPTION_KEY") {
		t.Errorf("the refusal does not name what is wrong: %v", err)
	}
}
