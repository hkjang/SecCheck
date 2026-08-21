package web

import (
	"archive/zip"
	"bytes"
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
		problem(w, 500, "EXPORT_FAILED", "심의 데이터를 내보내지 못했습니다.", nil)
		return
	}
	base := sanitizeFilename(fmt.Sprint(data.Review["review_number"]) + "-" + fmt.Sprint(data.Review["service_name"]))
	switch format {
	case "json":
		s.writeJSONExport(w, data, base)
	case "xlsx", "excel":
		s.writeExcelExport(w, data, base)
	case "pdf":
		s.writePDFExport(w, data, base)
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
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT si.item_code,si.section,si.category,si.title,si.question,si.severity,si.template_name,si.template_version,resp.applicability,resp.self_assessment,resp.current_state,resp.na_reason,resp.action_plan,rr.result,rr.opinion,rr.evidence_adequacy,rr.na_approved,rr.follow_up,COALESCE((SELECT jsonb_agg(jsonb_build_object('id',e.id,'filename',e.original_filename,'sha256',e.sha256,'version',e.current_version)) FROM evidences e WHERE e.submission_item_id=si.id AND e.deleted_at IS NULL),'[]') FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id LEFT JOIN responses resp ON resp.submission_item_id=si.id LEFT JOIN review_results rr ON rr.submission_item_id=si.id WHERE sub.review_request_id=$1 AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$1) ORDER BY si.template_name,si.sort_order`, id)
	if err != nil {
		return exportData{}, err
	}
	return exportData{Review: review, Items: scanDynamic(rows, []string{"item_code", "section", "category", "title", "question", "severity", "template_name", "template_version", "applicability", "self_assessment", "current_state", "na_reason", "action_plan", "review_result", "review_opinion", "evidence_adequacy", "na_approved", "follow_up", "evidences"})}, nil
}

func (s *Server) writeJSONExport(w http.ResponseWriter, data exportData, base string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename*=UTF-8''`+urlEncode(base+".json"))
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) writeExcelExport(w http.ResponseWriter, data exportData, base string) {
	f := excelize.NewFile()
	defer f.Close()
	summary := "심의 결과"
	f.SetSheetName("Sheet1", summary)
	summaryRows := [][]any{{"SecCheck 보안성 심의 결과"}, {"심의번호", data.Review["review_number"]}, {"서비스명", data.Review["service_name"]}, {"상태", data.Review["status"]}, {"작성자", data.Review["requester"]}, {"검토자", data.Review["reviewer"]}, {"승인자", data.Review["approver"]}, {"최초 제출일", data.Review["first_submitted_at"]}, {"최종 제출일", data.Review["final_submitted_at"]}, {"최종 승인일", data.Review["approved_at"]}, {"최종 결과", data.Review["final_result"]}, {"최종 의견", data.Review["final_opinion"]}}
	for y, row := range summaryRows {
		for x, v := range row {
			cell, _ := excelize.CoordinatesToCellName(x+1, y+1)
			_ = f.SetCellValue(summary, cell, v)
		}
	}
	itemsSheet := "항목별 결과"
	_, _ = f.NewSheet(itemsSheet)
	headers := []string{"템플릿", "버전", "항목코드", "구분", "분류", "보안요건", "점검질문", "중요도", "적용여부", "자체판단", "현황 및 증적", "N/A 사유", "조치내용", "검토결과", "검토의견", "증적 적정성", "후속조치"}
	for x, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(x+1, 1)
		_ = f.SetCellValue(itemsSheet, cell, h)
	}
	keys := []string{"template_name", "template_version", "item_code", "section", "category", "title", "question", "severity", "applicability", "self_assessment", "current_state", "na_reason", "action_plan", "review_result", "review_opinion", "evidence_adequacy", "follow_up"}
	for y, item := range data.Items {
		for x, k := range keys {
			cell, _ := excelize.CoordinatesToCellName(x+1, y+2)
			_ = f.SetCellValue(itemsSheet, cell, item[k])
		}
	}
	_ = f.SetColWidth(itemsSheet, "A", "Q", 20)
	_ = f.SetColWidth(itemsSheet, "F", "G", 42)
	buf, err := f.WriteToBuffer()
	if err != nil {
		problem(w, 500, "EXPORT_FAILED", "Excel 파일을 생성하지 못했습니다.", nil)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", `attachment; filename*=UTF-8''`+urlEncode(base+".xlsx"))
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) writePDFExport(w http.ResponseWriter, data exportData, base string) {
	font := findKoreanFont()
	if font == "" {
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
	fields := [][2]string{{"심의번호", fmt.Sprint(data.Review["review_number"])}, {"서비스명", fmt.Sprint(data.Review["service_name"])}, {"상태", fmt.Sprint(data.Review["status"])}, {"작성자", fmt.Sprint(data.Review["requester"])}, {"검토자", fmt.Sprint(data.Review["reviewer"])}, {"승인자", fmt.Sprint(data.Review["approver"])}, {"최종 결과", fmt.Sprint(data.Review["final_result"])}, {"최종 의견", fmt.Sprint(data.Review["final_opinion"])}}
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
		pdf.MultiCell(0, 5, detail, "B", "L", false)
		pdf.Ln(2)
	}
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		problem(w, 500, "EXPORT_FAILED", "PDF 파일을 생성하지 못했습니다.", nil)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename*=UTF-8''`+urlEncode(base+".pdf"))
	_, _ = w.Write(buf.Bytes())
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
		problem(w, 500, "EXPORT_FAILED", "증적 목록을 불러오지 못했습니다.", nil)
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
