// Package scanner runs malware scanning off the upload request. Uploads used
// to block on clamd for the whole file, which made a large attachment look
// like a hung browser tab. Evidence is now stored with scan_status PENDING and
// cleared here; until it reports CLEAN the download endpoint, the ZIP export
// and submission validation all refuse it, so the fail-closed guarantee holds.
package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/vault"
	"github.com/jackc/pgx/v5"
)

const (
	jobType     = "SCAN_EVIDENCE"
	maxAttempts = 5
	scanTimeout = 10 * time.Minute
)

type settings struct {
	Enabled bool   `json:"clamav_enabled"`
	Address string `json:"clamav_address"`
}

type Worker struct {
	Store *store.Store
	Vault *vault.Vault
}

func New(s *store.Store, v *vault.Vault) *Worker { return &Worker{Store: s, Vault: v} }

func (w *Worker) Run(ctx context.Context) {
	_, _ = w.Store.Pool.Exec(ctx, `UPDATE jobs SET status='PENDING',locked_at=NULL,available_at=now(),updated_at=now() WHERE type=$1 AND status='RUNNING' AND locked_at<now()-interval '15 minutes'`, jobType)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		for i := 0; i < 5; i++ {
			id, payload, attempt, err := w.claim(ctx)
			if errors.Is(err, pgx.ErrNoRows) {
				break
			}
			if err != nil {
				w.Store.Log(ctx, "ERROR", "", "scanner", "scan job claim failed", map[string]any{"error": err.Error()})
				break
			}
			if err = w.scan(ctx, payload); err != nil {
				w.fail(ctx, id, attempt, err)
				continue
			}
			_, _ = w.Store.Pool.Exec(ctx, `UPDATE jobs SET status='COMPLETED',locked_at=NULL,last_error='',updated_at=now() WHERE id=$1`, id)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Worker) claim(ctx context.Context) (string, []byte, int, error) {
	var id string
	var payload []byte
	var attempt int
	err := pgx.BeginFunc(ctx, w.Store.Pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE jobs SET status='RUNNING',attempts=attempts+1,locked_at=now(),updated_at=now() WHERE id=(SELECT id FROM jobs WHERE type=$1 AND status='PENDING' AND available_at<=now() ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,payload,attempts`, jobType).Scan(&id, &payload, &attempt)
	})
	return id, payload, attempt, err
}

func (w *Worker) scan(ctx context.Context, payload []byte) error {
	var job struct {
		EvidenceID string `json:"evidence_id"`
	}
	if err := json.Unmarshal(payload, &job); err != nil || job.EvidenceID == "" {
		return errors.New("invalid scan job payload")
	}
	var stored, owner, filename, status string
	var keyVersion, version int
	err := w.Store.Pool.QueryRow(ctx, `SELECT stored_filename,key_owner_id,key_version,current_version,original_filename,scan_status FROM evidences WHERE id=$1`, job.EvidenceID).
		Scan(&stored, &owner, &keyVersion, &version, &filename, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		// The evidence was deleted before the scan ran; nothing left to do.
		return nil
	}
	if err != nil {
		return err
	}
	if status != "PENDING" {
		return nil
	}
	var cfg settings
	if _, err = w.Store.Setting(ctx, "upload", &cfg); err != nil {
		return err
	}
	if !cfg.Enabled {
		// Scanning was switched off after the upload; release the file rather
		// than leaving it stuck behind a gate that no longer exists.
		return w.finish(ctx, job.EvidenceID, filename, "SKIPPED", "clamav disabled")
	}
	key, err := w.Vault.UserKey(ctx, owner, keyVersion)
	if err != nil {
		return err
	}
	reader, writer := io.Pipe()
	go func() {
		_, _, readErr := w.Vault.Read(writer, stored, key, vault.AAD(job.EvidenceID, version))
		_ = writer.CloseWithError(readErr)
	}()
	clean, detail, scanErr := Scan(bufio.NewReaderSize(reader, 64<<10), cfg.Address, scanTimeout)
	_ = reader.CloseWithError(nil)
	if scanErr != nil {
		return scanErr
	}
	if !clean {
		return w.quarantine(ctx, job.EvidenceID, filename, detail)
	}
	return w.finish(ctx, job.EvidenceID, filename, "CLEAN", detail)
}

func (w *Worker) finish(ctx context.Context, evidenceID, filename, status, detail string) error {
	// The clamd verdict is kept on the row, not only in the log, so the reason
	// a file was blocked is answerable months later. Both rows move together,
	// as they already do when a file is quarantined: nothing reads the version
	// level verdict today, but a history that disagrees with itself is a trap
	// for whoever reads it next.
	if err := pgx.BeginFunc(ctx, w.Store.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE evidences SET scan_status=$2,scan_detail=$3 WHERE id=$1`, evidenceID, status, truncate(detail, 500)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE evidence_versions SET scan_status=$2 WHERE evidence_id=$1 AND version=(SELECT current_version FROM evidences WHERE id=$1)`, evidenceID, status)
		return err
	}); err != nil {
		return err
	}
	w.Store.Log(ctx, "INFO", "", "scanner", "evidence scan completed", map[string]any{"evidence_id": evidenceID, "filename": filename, "status": status, "detail": detail})
	return nil
}

// quarantine marks the evidence infected, removes it from the checklist and
// tells the uploader, all in the same transaction as the status change.
func (w *Worker) quarantine(ctx context.Context, evidenceID, filename, detail string) error {
	var uploader, digest string
	if err := pgx.BeginFunc(ctx, w.Store.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `UPDATE evidences SET scan_status='INFECTED',scan_detail=$2,deleted_at=now() WHERE id=$1 RETURNING uploaded_by,sha256`, evidenceID, truncate(detail, 500)).Scan(&uploader, &digest); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE evidence_versions SET scan_status='INFECTED' WHERE evidence_id=$1`, evidenceID)
		return err
	}); err != nil {
		return err
	}
	// Deleting a file from a checklist is written to the chain when a person
	// does it. The scanner does the same thing to the same row, and left the
	// log with an item that quietly has one fewer file and no reason why.
	_ = w.Store.Audit(ctx, store.AuditEvent{UserName: "system", EventType: "QUARANTINE_EVIDENCE", TargetType: "EVIDENCE", TargetID: evidenceID,
		Before: map[string]any{"filename": filename, "sha256": digest}, After: map[string]any{"deleted": true, "scan_status": "INFECTED", "detail": truncate(detail, 300)}})

	// The file is already gone from the checklist, so this cannot be retried
	// without quarantining twice; but somebody whose upload was found to carry
	// malware has to be told, and losing that quietly is not acceptable.
	if err := w.Store.Notify(ctx, uploader, "EVIDENCE_INFECTED", "증적 악성코드 탐지",
		fmt.Sprintf("첨부하신 증적 %s에서 악성코드가 탐지되어 삭제되었습니다. 파일을 확인한 뒤 다시 업로드하세요.", filename), "EVIDENCE", evidenceID); err != nil {
		w.Store.Log(ctx, "ERROR", "", "scanner", "증적 격리는 완료했으나 업로더에게 알리지 못했습니다.", map[string]any{"evidence_id": evidenceID, "uploader": uploader, "error": truncate(err.Error(), 300)})
	}
	w.Store.Log(ctx, "ERROR", "", "scanner", "evidence quarantined", map[string]any{"evidence_id": evidenceID, "filename": filename, "detail": detail})
	return nil
}

func (w *Worker) fail(ctx context.Context, id string, attempt int, cause error) {
	status := "PENDING"
	if attempt >= maxAttempts {
		status = "FAILED"
	}
	delay := time.Duration(1<<min(attempt, 6)) * time.Minute
	_, _ = w.Store.Pool.Exec(ctx, `UPDATE jobs SET status=$2,available_at=now()+$3::interval,locked_at=NULL,last_error=$4,updated_at=now() WHERE id=$1`,
		id, status, fmt.Sprintf("%d seconds", int(delay.Seconds())), truncate(cause.Error(), 1000))
	if status == "FAILED" {
		// Give the administrator something actionable instead of an evidence
		// row stuck on PENDING for ever.
		var payload []byte
		if err := w.Store.Pool.QueryRow(ctx, `SELECT payload FROM jobs WHERE id=$1`, id).Scan(&payload); err == nil {
			var job struct {
				EvidenceID string `json:"evidence_id"`
			}
			if json.Unmarshal(payload, &job) == nil && job.EvidenceID != "" {
				_, _ = w.Store.Pool.Exec(ctx, `UPDATE evidences SET scan_status='ERROR',scan_detail=$2 WHERE id=$1 AND scan_status='PENDING'`, job.EvidenceID, truncate(cause.Error(), 500))
			}
		}
	}
	w.Store.Log(ctx, "ERROR", "", "scanner", "evidence scan failed", map[string]any{"job_id": id, "attempt": attempt, "terminal": status == "FAILED", "error": truncate(cause.Error(), 500)})
}

func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}

// Ping asks clamd whether it is there. Turning the scanner on used to be
// checked only for a non-empty address: a wrong host or port was discovered by
// uploads piling up unscanned, which blocks submission, and then by the queue
// alarm -- long after the setting was saved.
func Ping(address string, timeout time.Duration) (string, error) {
	if strings.TrimSpace(address) == "" {
		return "", errors.New("ClamAV address is not configured")
	}
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err = conn.Write([]byte("zPING\x00")); err != nil {
		return "", err
	}
	reply, err := io.ReadAll(io.LimitReader(conn, 64))
	if err != nil {
		return "", err
	}
	text := strings.TrimRight(string(reply), "\x00\n ")
	if !strings.EqualFold(text, "PONG") {
		return text, fmt.Errorf("unexpected reply: %s", truncateText(text, 60))
	}
	return text, nil
}

// Scan streams the plaintext to clamd with the INSTREAM protocol, so a
// large evidence file is never held in memory to be scanned.
func Scan(src io.Reader, address string, timeout time.Duration) (bool, string, error) {
	if address == "" {
		return false, "", errors.New("ClamAV address is not configured")
	}
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err = conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return false, "", err
	}
	writer := bufio.NewWriterSize(conn, 64<<10)
	chunk := make([]byte, 32<<10)
	for {
		n, readErr := src.Read(chunk)
		if n > 0 {
			header := []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
			if _, err = writer.Write(header); err != nil {
				return false, "", err
			}
			if _, err = writer.Write(chunk[:n]); err != nil {
				return false, "", err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return false, "", readErr
		}
	}
	if _, err = writer.Write([]byte{0, 0, 0, 0}); err != nil {
		return false, "", err
	}
	if err = writer.Flush(); err != nil {
		return false, "", err
	}
	response, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil {
		return false, "", err
	}
	text := strings.TrimRight(string(response), "\x00\n ")
	if strings.Contains(text, "FOUND") {
		return false, text, nil
	}
	if strings.Contains(text, "OK") {
		return true, text, nil
	}
	return false, text, fmt.Errorf("unexpected clamd response: %s", truncateText(text, 200))
}

func truncateText(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n] + "…"
}

// Scan states shared by the upload path, the background scanner and the UI.
const (
	scanSkipped  = "SKIPPED"
	scanPending  = "PENDING"
	scanClean    = "CLEAN"
	scanInfected = "INFECTED"
	scanError    = "ERROR"
)
