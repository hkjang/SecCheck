package web

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
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

// A rule that names a field the review form does not have can never match, so
// the item it guards silently stops appearing in reviews. That is a security
// requirement nobody is assessing and nobody was told about, and a typo is all
// it takes -- so it is refused at the point it is written.
func TestARuleCannotNameSomethingTheEngineWillNeverSee(t *testing.T) {
	known := ruleVocabulary()
	if len(known) < 10 || !known["exposure"] {
		t.Fatalf("the rule vocabulary does not look like the review form: %v", known)
	}
	rule := func(body string) any {
		t.Helper()
		var node any
		if err := json.Unmarshal([]byte(body), &node); err != nil {
			t.Fatal(err)
		}
		return node
	}
	for _, accepted := range []string{
		`{"field":"exposure","operator":"eq","value":"EXTERNAL"}`,
		`{"field":"has_admin_page","operator":"exists","value":true}`,
		`{"all":[{"field":"uses_cloud","operator":"eq","value":true},{"not":{"field":"internet_access","operator":"eq","value":false}}]}`,
		`{"any":[{"field":"service_type","operator":"in","value":["WEB","APP"]}]}`,
		`{"field":"business_criticality","value":"HIGH"}`,
	} {
		if err := checkedRule(rule(accepted)); err != nil {
			t.Errorf("a rule the engine understands was refused: %s -- %v", accepted, err)
		}
	}
	for _, refused := range []struct{ body, because string }{
		{`{"field":"exposure_level","operator":"eq","value":"EXTERNAL"}`, "a field the form does not have"},
		{`{"field":"exposure","operator":"matches","value":"EXTERNAL"}`, "an operator the engine does not have"},
		{`{"operator":"eq","value":"EXTERNAL"}`, "no field at all"},
		{`{"all":[]}`, "an empty group"},
		{`{"all":[{"field":"nope","operator":"eq","value":1}]}`, "an unknown field inside a group"},
		{`{"field":"service_type","operator":"in","value":"WEB"}`, "in without a list"},
		{`["exposure"]`, "not an object"},
	} {
		if err := checkedRule(rule(refused.body)); err == nil {
			t.Errorf("a rule with %s was accepted: %s", refused.because, refused.body)
		}
	}
	// No rule at all means the item always applies, which is not an error.
	if err := checkedRule(nil); err != nil {
		t.Errorf("an item without a rule was refused: %v", err)
	}
	if err := checkedRule(map[string]any{}); err != nil {
		t.Errorf("an empty rule was refused: %v", err)
	}
}

// "항목의 적용 규칙 조건을 만족하지 않습니다" says that something did not fit
// and leaves the reader to work out what. With a dozen conditions and twenty
// service characteristics, that is a puzzle the service can solve itself.
func TestARuleExplainsWhichConditionDidNotFit(t *testing.T) {
	fields := map[string]any{
		"service_type":            "WEB",
		"exposure":                "INTERNAL",
		"processes_personal_data": true,
		"uses_cloud":              false,
	}
	rule := []byte(`{"all":[
                {"field":"processes_personal_data","operator":"eq","value":true},
                {"field":"exposure","operator":"eq","value":"EXTERNAL"},
                {"not":{"field":"uses_cloud","operator":"eq","value":true}}
        ]}`)
	if evaluateRule(rule, fields) {
		t.Fatal("the fixture is meant to be a rule this service does not satisfy")
	}
	conditions := explainRule(rule, fields)
	if len(conditions) != 3 {
		t.Fatalf("the rule was explained as %d conditions, want 3: %+v", len(conditions), conditions)
	}
	// The explanation is the engine's own reading, not a second opinion: every
	// line says whether this service meets it.
	if !conditions[0].Matched || conditions[0].Field != "processes_personal_data" {
		t.Errorf("the condition this service does meet reads %+v", conditions[0])
	}
	if conditions[1].Matched || conditions[1].Field != "exposure" {
		t.Errorf("the condition that failed reads %+v", conditions[1])
	}
	if fmt.Sprint(conditions[1].Actual) != "INTERNAL" || fmt.Sprint(conditions[1].Value) != "EXTERNAL" {
		t.Errorf("the failing condition does not carry both sides: %+v", conditions[1])
	}
	// A negated condition is reported as satisfied when the service is on the
	// right side of the negation, or the reader would read the tick backwards.
	if !conditions[2].Negated || !conditions[2].Matched {
		t.Errorf("the negated condition reads %+v", conditions[2])
	}

	// A rule with no conditions has nothing to explain, and one the engine
	// cannot read explains nothing rather than inventing a reason.
	if got := explainRule([]byte(`{}`), fields); len(got) != 0 {
		t.Errorf("an empty rule was explained as %+v", got)
	}
	if got := explainRule([]byte(`{"all":`), fields); len(got) != 0 {
		t.Errorf("an unreadable rule was explained as %+v", got)
	}

	// Every condition the engine acts on is one the explanation shows: a rule
	// that matches is explained the same way, so "why is this item here" and
	// "why is it not" are answered from one implementation.
	matching := []byte(`{"any":[{"field":"exposure","operator":"in","value":["INTERNAL","EXTERNAL"]},{"field":"uses_cloud","operator":"eq","value":true}]}`)
	if !evaluateRule(matching, fields) {
		t.Fatal("the second fixture is meant to match")
	}
	got := explainRule(matching, fields)
	if len(got) != 2 || !got[0].Matched || got[1].Matched {
		t.Errorf("the matching rule was explained as %+v", got)
	}
}
