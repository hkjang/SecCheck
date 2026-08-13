package web

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/cryptox"
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
	data, name, mime, description, scan, err := s.readAndValidateEvidence(w, r)
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
		problem(w, 500, "KEY_UNAVAILABLE", "개인 암호화 키를 사용할 수 없습니다.", nil)
		return
	}
	id, stored := store.NewID(), store.NewID()+".enc"
	ciphertext, err := encryptWithKey(key, data, []byte("evidence:"+id+":1"))
	if err != nil {
		problem(w, 500, "ENCRYPTION_FAILED", "증적을 암호화하지 못했습니다.", nil)
		return
	}
	if err = s.writeEvidenceFile(stored, []byte(ciphertext)); err != nil {
		problem(w, 500, "STORAGE_FAILED", "증적을 저장하지 못했습니다.", nil)
		return
	}
	hash := sha256.Sum256(data)
	tx, err := s.Store.Pool.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO evidences(id,submission_item_id,original_filename,stored_filename,mime_type,size_bytes,sha256,uploaded_by,key_owner_id,key_version,description,scan_status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,$9,$10,$11)`, id, itemID, name, stored, mime, len(data), hex.EncodeToString(hash[:]), uid, version, description, scan)
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO evidence_versions(id,evidence_id,version,stored_filename,size_bytes,sha256,mime_type,key_owner_id,key_version,scan_status,uploaded_by) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$7)`, store.NewID(), id, stored, len(data), hex.EncodeToString(hash[:]), mime, uid, version, scan)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		} else {
			_ = tx.Rollback(r.Context())
		}
	}
	if err != nil {
		_ = os.Remove(s.evidencePath(stored))
		problem(w, 500, "UPLOAD_FAILED", "증적 정보를 저장하지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPLOAD_EVIDENCE", "EVIDENCE", id, nil, map[string]any{"filename": name, "size": len(data), "sha256": hex.EncodeToString(hash[:]), "scan_status": scan}))
	jsonResponse(w, 201, map[string]any{"id": id, "original_filename": name, "mime_type": mime, "size_bytes": len(data), "sha256": hex.EncodeToString(hash[:]), "scan_status": scan, "version": 1})
}

func (s *Server) newEvidenceVersion(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var reviewID string
	err := s.Store.Pool.QueryRow(r.Context(), `SELECT sub.review_request_id FROM evidences e JOIN submission_items si ON si.id=e.submission_item_id JOIN submissions sub ON sub.id=si.submission_id WHERE e.id=$1 AND e.deleted_at IS NULL`, id).Scan(&reviewID)
	if err != nil || !s.canEditReview(r.Context(), session(r), reviewID) {
		problem(w, 404, "NOT_FOUND", "증적을 찾을 수 없습니다.", nil)
		return
	}
	data, name, mime, _, scan, err := s.readAndValidateEvidence(w, r)
	if err != nil {
		problem(w, 422, "UPLOAD_REJECTED", err.Error(), nil)
		return
	}
	uid := session(r).User.ID
	key, keyVersion, err := s.activeUserKey(r.Context(), uid)
	if err != nil {
		problem(w, 500, "KEY_UNAVAILABLE", "개인 암호화 키를 사용할 수 없습니다.", nil)
		return
	}
	var version int
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT current_version+1 FROM evidences WHERE id=$1`, id).Scan(&version)
	stored := store.NewID() + ".enc"
	ciphertext, err := encryptWithKey(key, data, []byte(fmt.Sprintf("evidence:%s:%d", id, version)))
	if err != nil {
		problem(w, 500, "ENCRYPTION_FAILED", "증적을 암호화하지 못했습니다.", nil)
		return
	}
	if err = s.writeEvidenceFile(stored, []byte(ciphertext)); err != nil {
		problem(w, 500, "STORAGE_FAILED", "증적을 저장하지 못했습니다.", nil)
		return
	}
	hash := sha256.Sum256(data)
	tx, err := s.Store.Pool.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO evidence_versions(id,evidence_id,version,stored_filename,size_bytes,sha256,mime_type,key_owner_id,key_version,scan_status,uploaded_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$8)`, store.NewID(), id, version, stored, len(data), hex.EncodeToString(hash[:]), mime, uid, keyVersion, scan)
		if err == nil {
			_, err = tx.Exec(r.Context(), `UPDATE evidences SET original_filename=$2,stored_filename=$3,mime_type=$4,size_bytes=$5,sha256=$6,uploaded_by=$7,key_owner_id=$7,key_version=$8,scan_status=$9,current_version=$10 WHERE id=$1`, id, name, stored, mime, len(data), hex.EncodeToString(hash[:]), uid, keyVersion, scan, version)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		} else {
			_ = tx.Rollback(r.Context())
		}
	}
	if err != nil {
		_ = os.Remove(s.evidencePath(stored))
		problem(w, 500, "UPLOAD_FAILED", "새 증적 버전을 저장하지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPLOAD_EVIDENCE_VERSION", "EVIDENCE", id, nil, map[string]any{"version": version, "filename": name, "sha256": hex.EncodeToString(hash[:])}))
	jsonResponse(w, 201, map[string]any{"id": id, "version": version, "scan_status": scan})
}

func (s *Server) downloadEvidence(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var reviewID, name, stored, mime, owner, expectedHash string
	var version, keyVersion int
	err := s.Store.Pool.QueryRow(r.Context(), `SELECT sub.review_request_id,e.original_filename,e.stored_filename,e.mime_type,e.key_owner_id,e.current_version,e.key_version,e.sha256 FROM evidences e JOIN submission_items si ON si.id=e.submission_item_id JOIN submissions sub ON sub.id=si.submission_id WHERE e.id=$1 AND e.deleted_at IS NULL`, id).Scan(&reviewID, &name, &stored, &mime, &owner, &version, &keyVersion, &expectedHash)
	if err != nil || !s.canAccessReview(r.Context(), session(r), reviewID) {
		problem(w, 404, "NOT_FOUND", "증적을 찾을 수 없습니다.", nil)
		return
	}
	encoded, err := os.ReadFile(s.evidencePath(stored))
	if err != nil {
		problem(w, 500, "STORAGE_FAILED", "증적 파일을 읽지 못했습니다.", nil)
		return
	}
	key, err := s.userKey(r.Context(), owner, keyVersion)
	if err != nil {
		problem(w, 500, "KEY_UNAVAILABLE", "증적 암호화 키를 사용할 수 없습니다.", nil)
		return
	}
	plain, err := decryptWithKey(key, string(encoded), []byte(fmt.Sprintf("evidence:%s:%d", id, version)))
	if err != nil {
		problem(w, 500, "DECRYPTION_FAILED", "증적 무결성 검증에 실패했습니다.", nil)
		return
	}
	actualHash := sha256.Sum256(plain)
	if !strings.EqualFold(hex.EncodeToString(actualHash[:]), expectedHash) {
		problem(w, 500, "INTEGRITY_FAILED", "증적 SHA-256 무결성 검증에 실패했습니다.", nil)
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Disposition", `attachment; filename*=UTF-8''`+urlEncode(name))
	w.Header().Set("Content-Length", fmt.Sprint(len(plain)))
	_, _ = w.Write(plain)
	_ = s.Store.Audit(r.Context(), auditFrom(r, "DOWNLOAD_EVIDENCE", "EVIDENCE", id, nil, map[string]any{"filename": name, "version": version}))
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

func (s *Server) readAndValidateEvidence(w http.ResponseWriter, r *http.Request) ([]byte, string, string, string, string, error) {
	var cfg uploadSettings
	_, err := s.Store.Setting(r.Context(), "upload", &cfg)
	if err != nil {
		return nil, "", "", "", "", err
	}
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 25
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(cfg.MaxSizeMB+1)<<20)
	if err = r.ParseMultipartForm(int64(cfg.MaxSizeMB+1) << 20); err != nil {
		return nil, "", "", "", "", fmt.Errorf("파일 크기는 %dMB 이하여야 합니다", cfg.MaxSizeMB)
	}
	file, h, err := r.FormFile("file")
	if err != nil {
		return nil, "", "", "", "", errors.New("첨부 파일이 필요합니다")
	}
	defer file.Close()
	name := filepath.Base(h.Filename)
	if name == "." || name == "" || name != h.Filename && strings.ContainsAny(h.Filename, "/\\") {
		return nil, "", "", "", "", errors.New("안전하지 않은 파일명입니다")
	}
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
	if !contains(cfg.AllowedExtensions, ext) {
		return nil, "", "", "", "", fmt.Errorf("허용되지 않은 확장자입니다: %s", ext)
	}
	data, err := io.ReadAll(io.LimitReader(file, (int64(cfg.MaxSizeMB)<<20)+1))
	if err != nil {
		return nil, "", "", "", "", err
	}
	if len(data) > cfg.MaxSizeMB<<20 {
		return nil, "", "", "", "", fmt.Errorf("파일 크기는 %dMB 이하여야 합니다", cfg.MaxSizeMB)
	}
	if len(data) == 0 {
		return nil, "", "", "", "", errors.New("빈 파일은 업로드할 수 없습니다")
	}
	mime := http.DetectContentType(data[:min(len(data), 512)])
	if !mimeMatchesExtension(mime, ext, data) {
		return nil, "", "", "", "", fmt.Errorf("파일 내용과 확장자가 일치하지 않습니다 (%s)", mime)
	}
	scan := "SKIPPED"
	if cfg.ClamAVEnabled {
		clean, err := clamScan(data, cfg.ClamAVAddress)
		if err != nil {
			return nil, "", "", "", "", fmt.Errorf("악성코드 검사 실패: %v", err)
		}
		if !clean {
			return nil, "", "", "", "", errors.New("악성코드가 탐지되어 업로드가 차단되었습니다")
		}
		scan = "CLEAN"
	}
	return data, name, mime, r.FormValue("description"), scan, nil
}

func mimeMatchesExtension(detected, ext string, data []byte) bool {
	mediaType, _, err := mime.ParseMediaType(detected)
	if err == nil {
		detected = mediaType
	}
	allowed := map[string][]string{"pdf": {"application/pdf"}, "png": {"image/png"}, "jpg": {"image/jpeg"}, "jpeg": {"image/jpeg"}, "xlsx": {"application/zip", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}, "docx": {"application/zip", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}, "zip": {"application/zip"}, "txt": {"text/plain", "application/octet-stream"}, "json": {"text/plain", "application/json"}, "xls": {"application/octet-stream", "application/vnd.ms-excel"}}
	if ext == "xlsx" || ext == "docx" {
		return bytes.HasPrefix(data, []byte("PK\x03\x04")) && validOfficeArchive(data, ext)
	}
	if ext == "json" {
		return (detected == "text/plain" || detected == "application/json") && json.Valid(data)
	}
	if ext == "xls" {
		return len(data) >= 8 && bytes.Equal(data[:8], []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	}
	for _, v := range allowed[ext] {
		if detected == v {
			return true
		}
	}
	return false
}

func validOfficeArchive(data []byte, ext string) bool {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
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

func clamScan(data []byte, address string) (bool, error) {
	if address == "" {
		return false, errors.New("ClamAV address is not configured")
	}
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err = conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return false, err
	}
	for len(data) > 0 {
		n := min(len(data), 32*1024)
		header := []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
		if _, err = conn.Write(header); err != nil {
			return false, err
		}
		if _, err = conn.Write(data[:n]); err != nil {
			return false, err
		}
		data = data[n:]
	}
	_, _ = conn.Write([]byte{0, 0, 0, 0})
	response, err := io.ReadAll(io.LimitReader(conn, 1024))
	if err != nil {
		return false, err
	}
	text := string(response)
	if strings.Contains(text, "FOUND") {
		return false, nil
	}
	return strings.Contains(text, "OK"), nil
}

func (s *Server) activeUserKey(ctx context.Context, userID string) ([]byte, int, error) {
	if err := s.ensureUserDataKey(ctx, userID); err != nil {
		return nil, 0, err
	}
	var encrypted string
	var version int
	err := s.Store.Pool.QueryRow(ctx, `SELECT encrypted_key,version FROM user_data_keys WHERE user_id=$1 AND active ORDER BY version DESC LIMIT 1`, userID).Scan(&encrypted, &version)
	if err != nil {
		return nil, 0, err
	}
	plain, err := s.Box.Decrypt(encrypted, []byte(fmt.Sprintf("user-key:%s:%d", userID, version)))
	return plain, version, err
}
func (s *Server) userKey(ctx context.Context, userID string, version int) ([]byte, error) {
	var encrypted string
	err := s.Store.Pool.QueryRow(ctx, `SELECT encrypted_key FROM user_data_keys WHERE user_id=$1 AND version=$2`, userID, version).Scan(&encrypted)
	if err != nil {
		return nil, err
	}
	return s.Box.Decrypt(encrypted, []byte(fmt.Sprintf("user-key:%s:%d", userID, version)))
}

func encryptWithKey(key, plain, aad []byte) (string, error) {
	b, err := cryptox.New(key)
	if err != nil {
		return "", err
	}
	return b.Encrypt(plain, aad)
}
func decryptWithKey(key []byte, encoded string, aad []byte) ([]byte, error) {
	b, err := cryptox.New(key)
	if err != nil {
		return nil, err
	}
	return b.Decrypt(encoded, aad)
}

func (s *Server) writeEvidenceFile(name string, data []byte) error {
	dir := filepath.Join(s.DataDir, "evidence", name[:2])
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
func (s *Server) evidencePath(name string) string {
	if len(name) < 2 {
		return filepath.Join(s.DataDir, "evidence", "invalid")
	}
	return filepath.Join(s.DataDir, "evidence", name[:2], filepath.Base(name))
}
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
