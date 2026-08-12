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
	if !mimeMatchesExtension("application/json", "json", []byte(`{"ok":true}`)) || mimeMatchesExtension("application/json", "json", []byte(`not-json`)) {
		t.Fatal("JSON content validation failed")
	}
	var valid bytes.Buffer
	zw := zip.NewWriter(&valid)
	for _, name := range []string{"[Content_Types].xml", "xl/workbook.xml"} {
		f, _ := zw.Create(name)
		_, _ = f.Write([]byte("x"))
	}
	_ = zw.Close()
	if !mimeMatchesExtension("application/zip", "xlsx", valid.Bytes()) {
		t.Fatal("valid XLSX structure was rejected")
	}
	var generic bytes.Buffer
	zw = zip.NewWriter(&generic)
	f, _ := zw.Create("payload.txt")
	_, _ = f.Write([]byte("x"))
	_ = zw.Close()
	if mimeMatchesExtension("application/zip", "xlsx", generic.Bytes()) {
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
