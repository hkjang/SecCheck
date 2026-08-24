package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/app"
	"github.com/hkjang/SecCheck/internal/cryptox"
	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/vault"
)

// findOrphans lists encrypted files on the volume that no evidence version
// refers to. They are reported rather than deleted: an unexpected file on a
// storage volume is something an operator should look at, not something a
// maintenance job should quietly remove.
func findOrphans(ctx context.Context, db *store.Store, dataDir string, sampled bool) ([]string, int64) {
	if sampled {
		// A sample says nothing about which files are unreferenced.
		return nil, 0
	}
	known := map[string]bool{}
	rows, err := db.Pool.Query(ctx, `SELECT stored_filename FROM evidence_versions UNION SELECT stored_filename FROM evidences`)
	if err != nil {
		return nil, 0
	}
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil {
			known[name] = true
		}
	}
	rows.Close()

	var orphans []string
	var bytes int64
	root := filepath.Join(dataDir, "evidence")
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		if known[entry.Name()] {
			return nil
		}
		if info, statErr := entry.Info(); statErr == nil {
			bytes += info.Size()
		}
		orphans = append(orphans, path)
		return nil
	})
	sort.Strings(orphans)
	return orphans, bytes
}

// verifyEvidence walks every stored evidence file, decrypts it and compares
// the result against the size and SHA-256 recorded in the database. The
// operations guide asks for a recovery drill that proves the database backup
// and the evidence volume were captured at the same point; until now there was
// no way to actually prove it.
//
// Usage: seccheck verify-evidence [--json] [--sample N]
func verifyEvidence(args []string) int {
	asJSON := false
	sample := 0
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--json":
			asJSON = true
		case args[i] == "--sample" && i+1 < len(args):
			i++
			_, _ = fmt.Sscanf(args[i], "%d", &sample)
		case strings.HasPrefix(args[i], "--sample="):
			_, _ = fmt.Sscanf(strings.TrimPrefix(args[i], "--sample="), "%d", &sample)
		default:
			fmt.Fprintf(os.Stderr, "unknown argument %q\n", args[i])
			return 2
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()
	cfg, err := app.LoadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	db, err := store.Open(ctx, cfg.PostgresDSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect database: %v\n", err)
		return 2
	}
	defer db.Close()
	box, err := cryptox.New(cfg.EncryptionKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	blobs := vault.New(cfg.DataDir, box, db)

	// A purged blob is expected to be missing, so it is not a failure.
	query := `SELECT e.id,e.original_filename,e.stored_filename,e.key_owner_id,e.key_version,e.current_version,e.size_bytes,e.sha256 FROM evidences e WHERE e.deleted_at IS NULL AND e.purged_at IS NULL ORDER BY e.created_at`
	if sample > 0 {
		query = `SELECT e.id,e.original_filename,e.stored_filename,e.key_owner_id,e.key_version,e.current_version,e.size_bytes,e.sha256 FROM evidences e WHERE e.deleted_at IS NULL AND e.purged_at IS NULL ORDER BY random() LIMIT ` + fmt.Sprint(sample)
	}
	rows, err := db.Pool.Query(ctx, query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read evidence metadata: %v\n", err)
		return 2
	}
	type record struct {
		id, filename, stored, owner, digest string
		keyVersion, version                 int
		size                                int64
	}
	var records []record
	for rows.Next() {
		var rec record
		if err = rows.Scan(&rec.id, &rec.filename, &rec.stored, &rec.owner, &rec.keyVersion, &rec.version, &rec.size, &rec.digest); err != nil {
			rows.Close()
			fmt.Fprintf(os.Stderr, "read evidence metadata: %v\n", err)
			return 2
		}
		records = append(records, rec)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "read evidence metadata: %v\n", err)
		return 2
	}

	type failure struct {
		EvidenceID string `json:"evidence_id"`
		Filename   string `json:"filename"`
		Reason     string `json:"reason"`
	}
	var failures []failure
	var bytesChecked int64
	started := time.Now()
	for _, rec := range records {
		if reason := blobs.VerifyBlob(ctx, rec.id, rec.stored, rec.owner, rec.keyVersion, rec.version, rec.size, rec.digest); reason != "" {
			failures = append(failures, failure{rec.id, rec.filename, reason})
			continue
		}
		bytesChecked += rec.size
	}

	orphans, orphanBytes := findOrphans(ctx, db, cfg.DataDir, sample > 0)
	result := map[string]any{
		"orphan_files":  len(orphans),
		"orphan_bytes":  orphanBytes,
		"checked":       len(records),
		"passed":        len(records) - len(failures),
		"failed":        len(failures),
		"bytes_checked": bytesChecked,
		"duration_ms":   time.Since(started).Milliseconds(),
		"sampled":       sample > 0,
		"failures":      failures,
	}
	if asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(result)
	} else {
		fmt.Printf("증적 무결성 검증: %d건 중 %d건 통과, %d건 실패 (%.1f MB, %s)\n",
			len(records), len(records)-len(failures), len(failures),
			float64(bytesChecked)/(1024*1024), time.Since(started).Round(time.Millisecond))
		for _, f := range failures {
			fmt.Printf("  실패 %s (%s): %s\n", f.EvidenceID, f.Filename, f.Reason)
		}
		if len(orphans) > 0 {
			fmt.Printf("고아 파일 %d개 (%.1f MB): 데이터베이스에 대응 레코드가 없습니다.\n", len(orphans), float64(orphanBytes)/(1024*1024))
			for i, name := range orphans {
				if i == 10 {
					fmt.Printf("  ... 외 %d개\n", len(orphans)-10)
					break
				}
				fmt.Printf("  %s\n", name)
			}
		}
	}
	// A non-zero exit lets a recovery drill fail its own pipeline.
	if len(failures) > 0 {
		return 1
	}
	return 0
}
