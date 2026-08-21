package web

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"testing"
)

func TestEvaluateRule(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"all": []any{map[string]any{"field": "uses_cloud", "operator": "eq", "value": true}, map[string]any{"field": "exposure", "operator": "in", "value": []any{"EXTERNAL", "BOTH"}}}})
	if !evaluateRule(raw, map[string]any{"uses_cloud": true, "exposure": "EXTERNAL"}) {
		t.Fatal("matching compound rule did not apply")
	}
	if evaluateRule(raw, map[string]any{"uses_cloud": false, "exposure": "EXTERNAL"}) {
		t.Fatal("non-matching compound rule applied")
	}
}

func TestEvaluateRuleExistsNotAndNumeric(t *testing.T) {
	if !evalNode(map[string]any{"field": "missing", "operator": "exists", "value": false}, map[string]any{}) {
		t.Fatal("exists=false should match a missing field")
	}
	rule := map[string]any{"all": []any{map[string]any{"field": "score", "operator": "gte", "value": 7}, map[string]any{"not": map[string]any{"field": "exposure", "operator": "eq", "value": "INTERNAL"}}}}
	if !evalNode(rule, map[string]any{"score": 8, "exposure": "EXTERNAL"}) {
		t.Fatal("numeric/not compound rule did not apply")
	}
}

func TestEvidenceContentValidation(t *testing.T) {
	if !matches("application/json", "json", []byte(`{"ok":true}`)) || matches("application/json", "json", []byte(`not-json`)) {
		t.Fatal("JSON content validation failed")
	}
	var valid bytes.Buffer
	zw := zip.NewWriter(&valid)
	for _, name := range []string{"[Content_Types].xml", "xl/workbook.xml"} {
		f, _ := zw.Create(name)
		_, _ = f.Write([]byte("x"))
	}
	_ = zw.Close()
	if !matches("application/zip", "xlsx", valid.Bytes()) {
		t.Fatal("valid XLSX structure was rejected")
	}
	var generic bytes.Buffer
	zw = zip.NewWriter(&generic)
	f, _ := zw.Create("payload.txt")
	_, _ = f.Write([]byte("x"))
	_ = zw.Close()
	if matches("application/zip", "xlsx", generic.Bytes()) {
		t.Fatal("generic ZIP was accepted as XLSX")
	}
}

func TestImportNormalizesCodesAndDuplicates(t *testing.T) {
	rows := [][]string{{"구분", "항목코드", "보안 요건 항목", "항목설명"}, {"공통", "1.1000000000000001", "첫 항목", "질문"}, {"공통", "1.1", "중복 항목", "질문"}, {"공통", "", "코드 없는 항목", "질문"}}
	header, mapping := detectHeaders(rows)
	items := parseImportRows(rows, header, mapping, "CLOUD")
	if len(items) != 3 {
		t.Fatalf("got %d items", len(items))
	}
	if items[0].ItemCode != "1.1" || items[1].ItemCode != "1.1-DUP2" || items[2].ItemCode != "CLOUD-003" {
		t.Fatalf("unexpected codes: %q %q %q", items[0].ItemCode, items[1].ItemCode, items[2].ItemCode)
	}
}

// The import preview is a dry run: it must report what the parser will do to
// the workbook, not just echo the first few rows.
func TestImportReportExplainsWhatWillHappen(t *testing.T) {
	rows := [][]string{
		{"구분", "항목코드", "보안 요건 항목", "항목설명"},
		{"공통", "1.1", "첫 항목", "질문1"},
		{"공통", "1.1", "중복 코드 항목", "질문2"},
		{"공통", "", "코드 없는 항목", "질문3"},
		{"", "", "", ""},
		{"메모", "", "", "여기는 비고입니다"},
	}
	header, mapping := detectHeaders(rows)
	items, report := parseImportRowsWithReport(rows, header, mapping, "DEVELOPMENT")
	if report.Parsed != len(items) {
		t.Fatalf("report.Parsed=%d but %d items were produced", report.Parsed, len(items))
	}
	if report.Parsed != 4 {
		t.Errorf("parsed %d items, want 4 (three coded rows plus the note row that has a question)", report.Parsed)
	}
	if report.GeneratedCodes != 2 {
		t.Errorf("generated codes = %d, want 2", report.GeneratedCodes)
	}
	if len(report.DuplicateCodes) != 1 || report.DuplicateCodes[0] != "1.1" {
		t.Errorf("duplicate codes = %v, want [1.1]", report.DuplicateCodes)
	}
	if report.SkippedRows != 0 {
		t.Errorf("skipped rows = %d; a fully blank row is not counted as skipped work", report.SkippedRows)
	}
	if contains(report.MissingFields, "title") || contains(report.MissingFields, "item_code") {
		t.Errorf("mapped fields were reported as missing: %v", report.MissingFields)
	}
	if !contains(report.MissingFields, "severity") {
		t.Errorf("an unmapped column should be reported: %v", report.MissingFields)
	}
}
