package web

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/store"
	"github.com/phpdave11/gofpdf"
	"github.com/xuri/excelize/v2"
)

type exportData struct {
	Review map[string]any   `json:"review"`
	Items  []map[string]any `json:"items"`
}

func (s *Server) exportReview(w http.ResponseWriter, r *http.Request) {
	id, format := r.PathValue("id"), strings.ToLower(r.PathValue("format"))
	if !s.canAccessReview(r.Context(), session(r), id) {
		problem(w, 404, "NOT_FOUND", "심의를 찾을 수 없습니다.", nil)
		return
	}
	data, err := s.loadExportData(r, id)
	if err != nil {
		s.fault(w, r, "EXPORT_FAILED", "심의 데이터를 내보내지 못했습니다.", err)
		return
	}
	base := sanitizeFilename(fmt.Sprint(data.Review["review_number"]) + "-" + fmt.Sprint(data.Review["service_name"]))
	switch format {
	case "json":
		s.writeJSONExport(w, data, base)
	case "xlsx", "excel":
		s.writeExcelExport(w, r, data, base)
	case "pdf":
		s.writePDFExport(w, r, data, base)
	case "zip":
		s.writeZIPExport(w, r, data, base)
	default:
		problem(w, 404, "FORMAT_NOT_SUPPORTED", "지원 형식은 xlsx, pdf, json, zip입니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "EXPORT_DATA", "REVIEW_REQUEST", id, nil, map[string]string{"format": format}))
}

func (s *Server) loadExportData(r *http.Request, id string) (exportData, error) {
	var raw []byte
	err := s.Store.Pool.QueryRow(r.Context(), `SELECT to_jsonb(r)||jsonb_build_object('requester',requester.display_name,'reviewer',reviewer.display_name,'approver',approver.display_name,'templates',(SELECT COALESCE(jsonb_agg(DISTINCT jsonb_build_object('name',si.template_name,'version',si.template_version)),'[]') FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id WHERE sub.review_request_id=r.id)) FROM review_requests r JOIN users requester ON requester.id=r.requester_id LEFT JOIN users reviewer ON reviewer.id=r.reviewer_id LEFT JOIN users approver ON approver.id=r.approver_id WHERE r.id=$1`, id).Scan(&raw)
	if err != nil {
		return exportData{}, err
	}
	review := map[string]any{}
	_ = json.Unmarshal(raw, &review)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT si.item_code,si.section,si.category,si.title,si.question,si.severity,si.template_name,si.template_version,resp.applicability,resp.self_assessment,resp.current_state,resp.na_reason,resp.action_plan,rr.result,rr.opinion,rr.evidence_adequacy,rr.na_approved,rr.follow_up,to_char(rr.follow_up_due_date,'YYYY-MM-DD') AS follow_up_due_date,to_char(display_date(rr.follow_up_reported_at),'YYYY-MM-DD') AS follow_up_reported_on,to_char(display_date(rr.follow_up_done_at),'YYYY-MM-DD') AS follow_up_done_on,COALESCE((SELECT jsonb_agg(jsonb_build_object('id',e.id,'filename',e.original_filename,'sha256',e.sha256,'version',e.current_version)) FROM evidences e WHERE e.submission_item_id=si.id AND e.deleted_at IS NULL),'[]') FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id LEFT JOIN responses resp ON resp.submission_item_id=si.id LEFT JOIN review_results rr ON rr.submission_item_id=si.id WHERE sub.review_request_id=$1 AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$1) ORDER BY si.template_name,si.sort_order`, id)
	if err != nil {
		return exportData{}, err
	}
	return exportData{Review: review, Items: scanDynamic(rows, []string{"item_code", "section", "category", "title", "question", "severity", "template_name", "template_version", "applicability", "self_assessment", "current_state", "na_reason", "action_plan", "review_result", "review_opinion", "evidence_adequacy", "na_approved", "follow_up", "follow_up_due_date", "follow_up_reported_on", "follow_up_done_on", "evidences"})}, nil
}

// localTimestamp renders a stored timestamp in the configured display zone.
// Exports are read in spreadsheets and print-outs where the browser cannot
// convert anything, so UTC would simply be wrong by the offset.
func (s *Server) localTimestamp(v any) string {
	at, ok := store.AsTime(v)
	if !ok {
		return ""
	}
	return at.In(s.Store.Location(context.Background())).Format("2006-01-02 15:04")
}

func (s *Server) exportedAt() string {
	zone := s.Store.Location(context.Background())
	return time.Now().In(zone).Format("2006-01-02 15:04") + " (" + zone.String() + ")"
}

type exportEvidence struct {
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Version  int    `json:"version"`
}

// itemEvidence reads the evidence list that loadExportData already fetched.
// The report is the artefact that circulates, and until now it recorded the
// answers but never what was attached to support them, so a reader could not
// tell evidence from an assertion.
func itemEvidence(item map[string]any) []exportEvidence {
	raw, ok := item["evidences"].([]any)
	if !ok {
		return nil
	}
	out := make([]exportEvidence, 0, len(raw))
	for _, entry := range raw {
		record, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		version := 1
		if v, ok := record["version"].(float64); ok {
			version = int(v)
		}
		out = append(out, exportEvidence{
			Filename: fmt.Sprint(record["filename"]),
			SHA256:   fmt.Sprint(record["sha256"]),
			Version:  version,
		})
	}
	return out
}

func evidenceSummary(item map[string]any) string {
	files := itemEvidence(item)
	if len(files) == 0 {
		return ""
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Filename)
	}
	return strings.Join(names, ", ")
}

func (s *Server) writeJSONExport(w http.ResponseWriter, data exportData, base string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename*=UTF-8''`+urlEncode(base+".json"))
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) writeExcelExport(w http.ResponseWriter, r *http.Request, data exportData, base string) {
	f := excelize.NewFile()
	defer f.Close()
	summary := "심의 결과"
	f.SetSheetName("Sheet1", summary)
	when := func(key string) string { return s.localTimestamp(data.Review[key]) }
	summaryRows := [][]any{{"SecCheck 보안성 심의 결과"}, {"심의번호", data.Review["review_number"]}, {"서비스명", data.Review["service_name"]}, {"상태", data.Review["status"]}, {"작성자", data.Review["requester"]}, {"검토자", data.Review["reviewer"]}, {"승인자", data.Review["approver"]}, {"최초 제출일", when("first_submitted_at")}, {"최종 제출일", when("final_submitted_at")}, {"최종 승인일", when("approved_at")}, {"최종 결과", data.Review["final_result"]}, {"최종 의견", data.Review["final_opinion"]}, {"내보낸 시각", s.exportedAt()}}
	for y, row := range summaryRows {
		for x, v := range row {
			cell, _ := excelize.CoordinatesToCellName(x+1, y+1)
			_ = f.SetCellValue(summary, cell, spreadsheetValue(v))
		}
	}
	itemsSheet := "항목별 결과"
	_, _ = f.NewSheet(itemsSheet)
	headers := []string{"템플릿", "버전", "항목코드", "구분", "분류", "보안요건", "점검질문", "중요도", "적용여부", "자체판단", "현황 및 증적", "N/A 사유", "조치내용", "검토결과", "검토의견", "증적 적정성", "후속조치", "조치 기한", "이행 보고일", "이행 확인일", "첨부 증적"}
	for x, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(x+1, 1)
		_ = f.SetCellValue(itemsSheet, cell, h)
	}
	keys := []string{"template_name", "template_version", "item_code", "section", "category", "title", "question", "severity", "applicability", "self_assessment", "current_state", "na_reason", "action_plan", "review_result", "review_opinion", "evidence_adequacy", "follow_up", "follow_up_due_date", "follow_up_reported_on", "follow_up_done_on"}
	for y, item := range data.Items {
		for x, k := range keys {
			cell, _ := excelize.CoordinatesToCellName(x+1, y+2)
			_ = f.SetCellValue(itemsSheet, cell, spreadsheetValue(item[k]))
		}
		if cell, err := excelize.CoordinatesToCellName(len(keys)+1, y+2); err == nil {
			_ = f.SetCellValue(itemsSheet, cell, spreadsheetValue(evidenceSummary(item)))
		}
	}
	_ = f.SetColWidth(itemsSheet, "A", "R", 20)
	_ = f.SetColWidth(itemsSheet, "F", "G", 42)

	// A separate sheet lists every attachment with its hash, so the report can
	// be checked against the files without opening the archive.
	evidenceSheet := "증적 목록"
	if _, err := f.NewSheet(evidenceSheet); err == nil {
		evidenceRows := [][]any{{"항목코드", "보안요건", "파일명", "버전", "SHA-256"}}
		for _, item := range data.Items {
			for _, file := range itemEvidence(item) {
				evidenceRows = append(evidenceRows, []any{item["item_code"], item["title"], file.Filename, file.Version, file.SHA256})
			}
		}
		if len(evidenceRows) == 1 {
			evidenceRows = append(evidenceRows, []any{"", "첨부된 증적이 없습니다.", "", "", ""})
		}
		writeSheetRows(f, evidenceSheet, evidenceRows, 1)
		_ = f.SetColWidth(evidenceSheet, "A", "E", 24)
		_ = f.SetColWidth(evidenceSheet, "E", "E", 68)
	}
	buf, err := f.WriteToBuffer()
	if err != nil {
		s.fault(w, r, "EXPORT_FAILED", "Excel 파일을 생성하지 못했습니다.", err)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", `attachment; filename*=UTF-8''`+urlEncode(base+".xlsx"))
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) writePDFExport(w http.ResponseWriter, r *http.Request, data exportData, base string) {
	font := findKoreanFont()
	if font == "" {
		s.Store.Log(r.Context(), "ERROR", requestID(r), "api", "PDF 생성용 한글 글꼴이 설치되지 않았습니다.", map[string]any{"code": "FONT_MISSING", "path": r.URL.Path})
		problem(w, 500, "FONT_MISSING", "PDF 생성용 한글 글꼴이 설치되지 않았습니다.", nil)
		return
	}
	pdf := gofpdf.New("P", "mm", "A4", filepath.Dir(font))
	pdf.AddUTF8Font("kr", "", filepath.Base(font))
	pdf.SetMargins(14, 14, 14)
	pdf.SetAutoPageBreak(true, 14)
	pdf.AddPage()
	pdf.SetFont("kr", "", 18)
	pdf.CellFormat(0, 10, "SecCheck 보안성 심의 결과", "", 1, "L", false, 0, "")
	pdf.SetFont("kr", "", 10)
	fields := [][2]string{{"심의번호", fmt.Sprint(data.Review["review_number"])}, {"서비스명", fmt.Sprint(data.Review["service_name"])}, {"상태", fmt.Sprint(data.Review["status"])}, {"작성자", fmt.Sprint(data.Review["requester"])}, {"검토자", fmt.Sprint(data.Review["reviewer"])}, {"승인자", fmt.Sprint(data.Review["approver"])}, {"최초 제출일", s.localTimestamp(data.Review["first_submitted_at"])}, {"최종 승인일", s.localTimestamp(data.Review["approved_at"])}, {"최종 결과", fmt.Sprint(data.Review["final_result"])}, {"최종 의견", fmt.Sprint(data.Review["final_opinion"])}, {"내보낸 시각", s.exportedAt()}}
	for _, f := range fields {
		pdf.SetFont("kr", "", 9)
		pdf.CellFormat(32, 7, f[0], "B", 0, "L", false, 0, "")
		pdf.MultiCell(0, 7, f[1], "B", "L", false)
	}
	pdf.Ln(5)
	pdf.SetFont("kr", "", 14)
	pdf.CellFormat(0, 9, "항목별 검토 결과", "", 1, "L", false, 0, "")
	for i, item := range data.Items {
		pdf.SetFont("kr", "", 10)
		title := fmt.Sprintf("%d. [%v] %v", i+1, item["item_code"], item["title"])
		pdf.MultiCell(0, 6, title, "", "L", false)
		pdf.SetFont("kr", "", 8)
		detail := fmt.Sprintf("템플릿 %v %v | 적용여부 %v | 자체판단 %v | 검토결과 %v\n현황: %v\n검토의견: %v", item["template_name"], item["template_version"], item["applicability"], item["self_assessment"], item["review_result"], item["current_state"], item["review_opinion"])
		// What the team promised to do is the part of a conditional pass that
		// outlives the review, and the exported result did not carry it.
		if action := fmt.Sprint(valueOr(item["follow_up"], "")); strings.TrimSpace(action) != "" {
			detail += "\n후속조치: " + action
			if due := fmt.Sprint(valueOr(item["follow_up_due_date"], "")); due != "" {
				detail += " (기한 " + due
				switch {
				case fmt.Sprint(valueOr(item["follow_up_done_on"], "")) != "":
					detail += ", 이행 확인 " + fmt.Sprint(item["follow_up_done_on"]) + ")"
				case fmt.Sprint(valueOr(item["follow_up_reported_on"], "")) != "":
					detail += ", 이행 보고 " + fmt.Sprint(item["follow_up_reported_on"]) + ")"
				default:
					detail += ", 미조치)"
				}
			}
		}
		if files := itemEvidence(item); len(files) > 0 {
			for _, file := range files {
				detail += fmt.Sprintf("\n증적: %s (v%d, SHA-256 %s)", file.Filename, file.Version, file.SHA256)
			}
		}
		pdf.MultiCell(0, 5, detail, "B", "L", false)
		pdf.Ln(2)
	}
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		s.fault(w, r, "EXPORT_FAILED", "PDF 파일을 생성하지 못했습니다.", err)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename*=UTF-8''`+urlEncode(base+".pdf"))
	_, _ = w.Write(buf.Bytes())
}

// valueOr keeps a null column out of the rendered text, where fmt would
// otherwise print "<nil>".
func valueOr(v any, fallback string) any {
	if v == nil {
		return fallback
	}
	return v
}

func findKoreanFont() string {
	paths := []string{"/usr/share/fonts/truetype/nanum/NanumGothic.ttf", "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", "C:\\Windows\\Fonts\\malgun.ttf"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// writeZIPExport streams the archive to the client. A review with many large
// evidence files used to be assembled in memory in full before the first byte
// was sent.
func (s *Server) writeZIPExport(w http.ResponseWriter, r *http.Request, data exportData, base string) {
	reviewID := r.PathValue("id")
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT e.id,e.original_filename,e.stored_filename,e.key_owner_id,e.key_version,e.current_version,e.scan_status FROM evidences e JOIN submission_items si ON si.id=e.submission_item_id JOIN submissions sub ON sub.id=si.submission_id WHERE sub.review_request_id=$1 AND e.deleted_at IS NULL ORDER BY e.created_at`, reviewID)
	if err != nil {
		s.fault(w, r, "EXPORT_FAILED", "증적 목록을 불러오지 못했습니다.", err)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename*=UTF-8''`+urlEncode(base+".zip"))
	zw := zip.NewWriter(w)
	defer zw.Close()
	manifest, err := zw.Create("result.json")
	if err != nil {
		return
	}
	if err = json.NewEncoder(manifest).Encode(data); err != nil {
		return
	}
	used := map[string]int{}
	var skipped []string
	for rows.Next() {
		var id, name, stored, owner, scanStatus string
		var keyVersion, version int
		if rows.Scan(&id, &name, &stored, &owner, &keyVersion, &version, &scanStatus) != nil {
			continue
		}
		// Unscanned or infected files are withheld here for the same reason the
		// download endpoint refuses them.
		if scanStatus != scanClean && scanStatus != scanSkipped {
			skipped = append(skipped, name+" ("+scanStatus+")")
			continue
		}
		key, keyErr := s.userKey(r.Context(), owner, keyVersion)
		if keyErr != nil {
			skipped = append(skipped, name+" (KEY_UNAVAILABLE)")
			continue
		}
		safe := sanitizeFilename(name)
		used[safe]++
		if used[safe] > 1 {
			ext := filepath.Ext(safe)
			safe = strings.TrimSuffix(safe, ext) + "-" + strconv.Itoa(used[safe]) + ext
		}
		entry, createErr := zw.Create("evidence/" + safe)
		if createErr != nil {
			return
		}
		if _, _, readErr := s.readEvidenceStream(entry, stored, key, []byte(fmt.Sprintf("evidence:%s:%d", id, version))); readErr != nil {
			s.Store.Log(r.Context(), "ERROR", requestID(r), "export", "evidence could not be added to the archive", map[string]any{"evidence_id": id, "error": readErr.Error()})
			return
		}
	}
	if len(skipped) > 0 {
		if note, noteErr := zw.Create("evidence/EXCLUDED.txt"); noteErr == nil {
			_, _ = io.WriteString(note, "다음 증적은 악성코드 검사 상태 또는 키 문제로 포함되지 않았습니다.\n\n"+strings.Join(skipped, "\n")+"\n")
		}
	}
}

var _ = time.Now
var _ = store.NewID
