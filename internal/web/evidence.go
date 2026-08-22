package web

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hkjang/SecCheck/internal/store"
)

type uploadSettings struct {
	MaxSizeMB         int      `json:"max_size_mb"`
	AllowedExtensions []string `json:"allowed_extensions"`
	ClamAVEnabled     bool     `json:"clamav_enabled"`
	ClamAVAddress     string   `json:"clamav_address"`
}

func (s *Server) uploadEvidence(w http.ResponseWriter, r *http.Request) {
	reviewID, itemID := r.PathValue("id"), r.PathValue("itemID")
	if !s.canEditReview(r.Context(), session(r), reviewID) {
		problem(w, 403, "FORBIDDEN", "이 심의에 증적을 첨부할 수 없습니다.", nil)
		return
	}
	upload, err := s.readAndValidateEvidence(w, r)
	if err != nil {
		problem(w, 422, "UPLOAD_REJECTED", err.Error(), nil)
		return
	}
	if !s.itemBelongsToReview(r.Context(), itemID, reviewID) {
		problem(w, 404, "NOT_FOUND", "체크리스트 항목을 찾을 수 없습니다.", nil)
		return
	}
	uid := session(r).User.ID
	key, version, err := s.activeUserKey(r.Context(), uid)
	if err != nil {
		s.fault(w, r, "KEY_UNAVAILABLE", "개인 암호화 키를 사용할 수 없습니다.", err)
		return
	}
	id, stored := store.NewID(), store.NewID()+".enc"
	size, digest, err := s.writeEvidenceStream(stored, key, []byte("evidence:"+id+":1"), upload.File)
	if err != nil {
		s.fault(w, r, "STORAGE_FAILED", "증적을 저장하지 못했습니다.", err)
		return
	}
	tx, err := s.Store.Pool.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO evidences(id,submission_item_id,original_filename,stored_filename,mime_type,size_bytes,sha256,uploaded_by,key_owner_id,key_version,description,scan_status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,$9,$10,$11)`, id, itemID, upload.Name, stored, upload.MIME, size, digest, uid, version, upload.Description, upload.Scan)
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO evidence_versions(id,evidence_id,version,stored_filename,size_bytes,sha256,mime_type,key_owner_id,key_version,scan_status,uploaded_by) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$7)`, store.NewID(), id, stored, size, digest, upload.MIME, uid, version, upload.Scan)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		} else {
			_ = tx.Rollback(r.Context())
		}
	}
	if err != nil {
		_ = os.Remove(s.evidencePath(stored))
		s.fault(w, r, "UPLOAD_FAILED", "증적 정보를 저장하지 못했습니다.", err)
		return
	}
	s.enqueueScan(r.Context(), id, upload.Scan)
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPLOAD_EVIDENCE", "EVIDENCE", id, nil, map[string]any{"filename": upload.Name, "size": size, "sha256": digest, "scan_status": upload.Scan}))
	jsonResponse(w, 201, map[string]any{"id": id, "original_filename": upload.Name, "mime_type": upload.MIME, "size_bytes": size, "sha256": digest, "scan_status": upload.Scan, "version": 1})
}

// enqueueScan hands large-file malware scanning to the background queue so an
// upload no longer blocks on clamd. Until the scan reports CLEAN the evidence
// cannot be downloaded and submission validation keeps rejecting it, so the
// fail-closed guarantee is preserved.
func (s *Server) enqueueScan(ctx context.Context, evidenceID, status string) {
	if status != scanPending {
		return
	}
	payload, _ := json.Marshal(map[string]string{"evidence_id": evidenceID})
	_, _ = s.Store.Pool.Exec(ctx, `INSERT INTO jobs(id,type,payload) VALUES($1,'SCAN_EVIDENCE',$2)`, store.NewID(), payload)
}

func (s *Server) newEvidenceVersion(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var reviewID string
	err := s.Store.Pool.QueryRow(r.Context(), `SELECT sub.review_request_id FROM evidences e JOIN submission_items si ON si.id=e.submission_item_id JOIN submissions sub ON sub.id=si.submission_id WHERE e.id=$1 AND e.deleted_at IS NULL`, id).Scan(&reviewID)
	if err != nil || !s.canEditReview(r.Context(), session(r), reviewID) {
		problem(w, 404, "NOT_FOUND", "증적을 찾을 수 없습니다.", nil)
		return
	}
	upload, err := s.readAndValidateEvidence(w, r)
	if err != nil {
		problem(w, 422, "UPLOAD_REJECTED", err.Error(), nil)
		return
	}
	uid := session(r).User.ID
	key, keyVersion, err := s.activeUserKey(r.Context(), uid)
	if err != nil {
		s.fault(w, r, "KEY_UNAVAILABLE", "개인 암호화 키를 사용할 수 없습니다.", err)
		return
	}
	var version int
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT current_version+1 FROM evidences WHERE id=$1`, id).Scan(&version)
	stored := store.NewID() + ".enc"
	size, digest, err := s.writeEvidenceStream(stored, key, []byte(fmt.Sprintf("evidence:%s:%d", id, version)), upload.File)
	if err != nil {
		s.fault(w, r, "STORAGE_FAILED", "증적을 저장하지 못했습니다.", err)
		return
	}
	tx, err := s.Store.Pool.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO evidence_versions(id,evidence_id,version,stored_filename,size_bytes,sha256,mime_type,key_owner_id,key_version,scan_status,uploaded_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$8)`, store.NewID(), id, version, stored, size, digest, upload.MIME, uid, keyVersion, upload.Scan)
		if err == nil {
			_, err = tx.Exec(r.Context(), `UPDATE evidences SET original_filename=$2,stored_filename=$3,mime_type=$4,size_bytes=$5,sha256=$6,uploaded_by=$7,key_owner_id=$7,key_version=$8,scan_status=$9,current_version=$10 WHERE id=$1`, id, upload.Name, stored, upload.MIME, size, digest, uid, keyVersion, upload.Scan, version)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		} else {
			_ = tx.Rollback(r.Context())
		}
	}
	if err != nil {
		_ = os.Remove(s.evidencePath(stored))
		s.fault(w, r, "UPLOAD_FAILED", "새 증적 버전을 저장하지 못했습니다.", err)
		return
	}
	s.enqueueScan(r.Context(), id, upload.Scan)
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPLOAD_EVIDENCE_VERSION", "EVIDENCE", id, nil, map[string]any{"version": version, "filename": upload.Name, "sha256": digest}))
	jsonResponse(w, 201, map[string]any{"id": id, "version": version, "scan_status": upload.Scan})
}

func (s *Server) downloadEvidence(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var reviewID, name, stored, mime, owner, expectedHash string
	var version, keyVersion int
	var scanStatus string
	var size int64
	err := s.Store.Pool.QueryRow(r.Context(), `SELECT sub.review_request_id,e.original_filename,e.stored_filename,e.mime_type,e.key_owner_id,e.current_version,e.key_version,e.sha256,e.scan_status,e.size_bytes FROM evidences e JOIN submission_items si ON si.id=e.submission_item_id JOIN submissions sub ON sub.id=si.submission_id WHERE e.id=$1 AND e.deleted_at IS NULL`, id).Scan(&reviewID, &name, &stored, &mime, &owner, &version, &keyVersion, &expectedHash, &scanStatus, &size)
	if err != nil || !s.canAccessReview(r.Context(), session(r), reviewID) {
		problem(w, 404, "NOT_FOUND", "증적을 찾을 수 없습니다.", nil)
		return
	}
	// Scanning is asynchronous, so a file that has not been cleared yet must
	// not leave the server.
	if scanStatus != scanClean && scanStatus != scanSkipped {
		_ = s.Store.Audit(r.Context(), auditFrom(r, "DOWNLOAD_EVIDENCE", "EVIDENCE", id, nil, map[string]any{"filename": name, "scan_status": scanStatus, "blocked": true}))
		var detail string
		_ = s.Store.Pool.QueryRow(r.Context(), `SELECT scan_detail FROM evidences WHERE id=$1`, id).Scan(&detail)
		problem(w, 409, "SCAN_NOT_CLEARED", scanBlockMessage(scanStatus), map[string]any{"scan_status": scanStatus, "scan_detail": detail})
		return
	}
	key, err := s.userKey(r.Context(), owner, keyVersion)
	if err != nil {
		s.fault(w, r, "KEY_UNAVAILABLE", "증적 암호화 키를 사용할 수 없습니다.", err)
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Disposition", `attachment; filename*=UTF-8''`+urlEncode(name))
	w.Header().Set("Content-Length", fmt.Sprint(size))
	// Every chunk is authenticated as it is decrypted, so a tampered file stops
	// the transfer part-way; the declared Content-Length makes that visible to
	// the client instead of looking like a complete download.
	written, digest, err := s.readEvidenceStream(w, stored, key, []byte(fmt.Sprintf("evidence:%s:%d", id, version)))
	if err != nil {
		s.Store.Log(r.Context(), "ERROR", requestID(r), "evidence", "evidence download failed", map[string]any{"evidence_id": id, "error": err.Error()})
		_ = s.Store.Audit(r.Context(), store.AuditEvent{UserID: session(r).User.ID, UserName: session(r).User.DisplayName, SourceIP: clientIP(r), SessionID: session(r).ID, EventType: "DOWNLOAD_EVIDENCE", TargetType: "EVIDENCE", TargetID: id, RequestID: requestID(r), Result: "FAILURE", After: map[string]any{"filename": name, "error": err.Error()}})
		return
	}
	if written != size || !strings.EqualFold(digest, expectedHash) {
		s.Store.Log(r.Context(), "ERROR", requestID(r), "evidence", "evidence integrity mismatch", map[string]any{"evidence_id": id, "expected_sha256": expectedHash, "actual_sha256": digest, "expected_size": size, "actual_size": written})
		_ = s.Store.Audit(r.Context(), store.AuditEvent{UserID: session(r).User.ID, UserName: session(r).User.DisplayName, SourceIP: clientIP(r), SessionID: session(r).ID, EventType: "DOWNLOAD_EVIDENCE", TargetType: "EVIDENCE", TargetID: id, RequestID: requestID(r), Result: "FAILURE", After: map[string]any{"filename": name, "reason": "sha256 mismatch"}})
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "DOWNLOAD_EVIDENCE", "EVIDENCE", id, nil, map[string]any{"filename": name, "version": version, "size": written}))
}

func scanBlockMessage(status string) string {
	if status == scanInfected {
		return "악성코드가 탐지된 증적입니다. 다시 업로드하세요."
	}
	if status == scanError {
		return "악성코드 검사에 실패한 증적입니다. 관리자에게 문의하세요."
	}
	return "악성코드 검사가 진행 중입니다. 잠시 후 다시 시도하세요."
}

func (s *Server) deleteEvidence(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var reviewID, name, hash string
	err := s.Store.Pool.QueryRow(r.Context(), `SELECT sub.review_request_id,e.original_filename,e.sha256 FROM evidences e JOIN submission_items si ON si.id=e.submission_item_id JOIN submissions sub ON sub.id=si.submission_id WHERE e.id=$1 AND e.deleted_at IS NULL`, id).Scan(&reviewID, &name, &hash)
	if err != nil || !s.canEditReview(r.Context(), session(r), reviewID) {
		problem(w, 404, "NOT_FOUND", "삭제할 증적을 찾을 수 없습니다.", nil)
		return
	}
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE evidences SET deleted_at=now() WHERE id=$1 AND deleted_at IS NULL`, id)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "DELETE_FAILED", "증적을 삭제하지 못했습니다.", nil)
		return
	}
	// Physical encrypted versions remain under the configured retention policy;
	// the logical deletion and immutable metadata are audit-visible.
	_ = s.Store.Audit(r.Context(), auditFrom(r, "DELETE_EVIDENCE", "EVIDENCE", id, map[string]any{"filename": name, "sha256": hash}, map[string]any{"deleted": true}))
	w.WriteHeader(http.StatusNoContent)
}

// evidenceUpload carries a validated upload that is still on disk in the
// multipart spool rather than on the heap. Callers stream File straight into
// the encryptor.
type evidenceUpload struct {
	File        multipart.File
	Size        int64
	Name        string
	MIME        string
	Description string
	Scan        string
}

// spoolThreshold is how much of a multipart body stays in memory; the rest is
// written to a temporary file that net/http removes when the request ends.
const spoolThreshold = 8 << 20

func (s *Server) readAndValidateEvidence(w http.ResponseWriter, r *http.Request) (*evidenceUpload, error) {
	var cfg uploadSettings
	_, err := s.Store.Setting(r.Context(), "upload", &cfg)
	if err != nil {
		return nil, err
	}
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 25
	}
	limit := int64(cfg.MaxSizeMB) << 20
	r.Body = http.MaxBytesReader(w, r.Body, limit+(1<<20))
	if err = r.ParseMultipartForm(spoolThreshold); err != nil {
		return nil, fmt.Errorf("파일 크기는 %dMB 이하여야 합니다", cfg.MaxSizeMB)
	}
	file, h, err := r.FormFile("file")
	if err != nil {
		return nil, errors.New("첨부 파일이 필요합니다")
	}
	name := filepath.Base(h.Filename)
	if name == "." || name == "" || name != h.Filename && strings.ContainsAny(h.Filename, "/\\") {
		return nil, errors.New("안전하지 않은 파일명입니다")
	}
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
	if !contains(cfg.AllowedExtensions, ext) {
		return nil, fmt.Errorf("허용되지 않은 확장자입니다: %s", ext)
	}
	size, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	if size > limit {
		return nil, fmt.Errorf("파일 크기는 %dMB 이하여야 합니다", cfg.MaxSizeMB)
	}
	if size == 0 {
		return nil, errors.New("빈 파일은 업로드할 수 없습니다")
	}
	prefix := make([]byte, min(int(size), 512))
	if _, err = file.ReadAt(prefix, 0); err != nil && err != io.EOF {
		return nil, err
	}
	detected := http.DetectContentType(prefix)
	if !mimeMatchesExtension(detected, ext, file, size, prefix) {
		return nil, fmt.Errorf("파일 내용과 확장자가 일치하지 않습니다 (%s)", detected)
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	scan := scanSkipped
	if cfg.ClamAVEnabled {
		scan = scanPending
	}
	return &evidenceUpload{File: file, Size: size, Name: name, MIME: detected, Description: r.FormValue("description"), Scan: scan}, nil
}

// mimeMatchesExtension inspects the upload through its ReaderAt so that
// container formats can be validated without loading the file into memory.
func mimeMatchesExtension(detected, ext string, file io.ReaderAt, size int64, prefix []byte) bool {
	mediaType, _, err := mime.ParseMediaType(detected)
	if err == nil {
		detected = mediaType
	}
	allowed := map[string][]string{"pdf": {"application/pdf"}, "png": {"image/png"}, "jpg": {"image/jpeg"}, "jpeg": {"image/jpeg"}, "xlsx": {"application/zip", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}, "docx": {"application/zip", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}, "zip": {"application/zip"}, "txt": {"text/plain", "application/octet-stream"}, "json": {"text/plain", "application/json"}, "xls": {"application/octet-stream", "application/vnd.ms-excel"}}
	if ext == "xlsx" || ext == "docx" {
		return bytes.HasPrefix(prefix, []byte("PK\x03\x04")) && validOfficeArchive(file, size, ext)
	}
	if ext == "json" {
		return (detected == "text/plain" || detected == "application/json") && validJSONDocument(file, size)
	}
	if ext == "xls" {
		return len(prefix) >= 8 && bytes.Equal(prefix[:8], []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	}
	for _, v := range allowed[ext] {
		if detected == v {
			return true
		}
	}
	return false
}

func validOfficeArchive(file io.ReaderAt, size int64, ext string) bool {
	zr, err := zip.NewReader(file, size)
	if err != nil {
		return false
	}
	required := "xl/workbook.xml"
	if ext == "docx" {
		required = "word/document.xml"
	}
	hasTypes, hasDocument := false, false
	for _, f := range zr.File {
		name := strings.ReplaceAll(f.Name, "\\", "/")
		if name == "[Content_Types].xml" {
			hasTypes = true
		}
		if name == required {
			hasDocument = true
		}
	}
	return hasTypes && hasDocument
}

// validJSONDocument streams the document instead of buffering it, and rejects
// trailing content the way json.Valid would.
func validJSONDocument(file io.ReaderAt, size int64) bool {
	decoder := json.NewDecoder(bufio.NewReaderSize(io.NewSectionReader(file, 0, size), 64<<10))
	var document json.RawMessage
	if err := decoder.Decode(&document); err != nil {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

// Scan states shared by the upload path, the background scanner and the UI.
const (
	scanSkipped  = "SKIPPED"
	scanPending  = "PENDING"
	scanClean    = "CLEAN"
	scanInfected = "INFECTED"
	scanError    = "ERROR"
)

func (s *Server) writeEvidenceStream(name string, key, aad []byte, src io.Reader) (int64, string, error) {
	return s.vault().Write(name, key, aad, src)
}

func (s *Server) readEvidenceStream(dst io.Writer, name string, key, aad []byte) (int64, string, error) {
	return s.vault().Read(dst, name, key, aad)
}

func (s *Server) activeUserKey(ctx context.Context, userID string) ([]byte, int, error) {
	return s.vault().ActiveUserKey(ctx, userID)
}

func (s *Server) userKey(ctx context.Context, userID string, version int) ([]byte, error) {
	return s.vault().UserKey(ctx, userID, version)
}

func (s *Server) evidencePath(name string) string { return s.vault().Path(name) }
func (s *Server) itemBelongsToReview(ctx context.Context, itemID, reviewID string) bool {
	var ok bool
	_ = s.Store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM submission_items si JOIN submissions sub ON sub.id=si.submission_id WHERE si.id=$1 AND sub.review_request_id=$2)`, itemID, reviewID).Scan(&ok)
	return ok
}

func (s *Server) itemBelongsToLatestSubmission(ctx context.Context, itemID, reviewID string) bool {
	var ok bool
	_ = s.Store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM submission_items si JOIN submissions sub ON sub.id=si.submission_id WHERE si.id=$1 AND sub.review_request_id=$2 AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$2))`, itemID, reviewID).Scan(&ok)
	return ok
}
