package web

import (
	"strings"
	"testing"
)

func mappingOf(rows [][]string) string {
	_, mapping := detectHeaders(rows)
	parts := []string{}
	for _, m := range mapping {
		parts = append(parts, m.Header+"="+m.Field)
	}
	return strings.Join(parts, " ")
}

// The guess used to come out of a map range, so the same workbook produced a
// different column mapping from one upload to the next -- and the wizard
// submits whatever it was shown.
func TestHeaderGuessIsTheSameEveryTime(t *testing.T) {
	rows := [][]string{{"구분", "구분 No.", "보안 요건 항목", "점검항목", "점검 가이드", "관련 근거", "현황 및 증적", "중요도"}}
	first := mappingOf(rows)
	for i := 0; i < 200; i++ {
		if got := mappingOf(rows); got != first {
			t.Fatalf("run %d produced a different mapping:\n%s\n%s", i, first, got)
		}
	}
}

func TestAmbiguousHeadersResolveToTheRightField(t *testing.T) {
	for _, tc := range []struct{ header, want string }{
		{"구분", "section"},
		{"구분 No.", "item_code"}, // contains "구분" but exactly matches the code alias
		{"구분 no", "item_code"},
		{"항목코드", "item_code"},
		{"보안 요건 항목", "title"},
		{"점검항목", "question"}, // the question, not the requirement title
		{"점검 가이드", "guide"},
		{"중요도", "severity"},
		{"비고", ""},
	} {
		if got := matchField(tc.header, map[string]bool{}); got != tc.want {
			t.Errorf("matchField(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

// Two columns must never claim the same field while a real column goes
// unmapped: that is how a sheet lost its item codes and had them regenerated.
func TestEachFieldIsClaimedByOneColumn(t *testing.T) {
	rows := [][]string{{"구분", "구분 No.", "보안 요건 항목", "점검항목"}}
	_, mapping := detectHeaders(rows)
	seen := map[string]string{}
	for _, m := range mapping {
		if prior, dup := seen[m.Field]; dup {
			t.Errorf("%q and %q both map to %s", prior, m.Header, m.Field)
		}
		seen[m.Field] = m.Header
	}
	for _, field := range []string{"section", "item_code", "title", "question"} {
		if seen[field] == "" {
			t.Errorf("no column mapped to %s: %v", field, seen)
		}
	}
}

// A sheet that only carries the question still has to produce a title.
func TestASheetWithOnlyAQuestionStillYieldsItems(t *testing.T) {
	rows := [][]string{{"점검항목", "중요도"}, {"관리자 계정의 비밀번호는 90일마다 변경되는가?", "상"}}
	header, mapping := detectHeaders(rows)
	items, report := parseImportRowsWithReport(rows, header, mapping, "DEVELOPMENT")
	if len(items) != 1 {
		t.Fatalf("parsed %d items, want 1 (report %+v)", len(items), report)
	}
	if items[0].Title == "" || items[0].Question == "" {
		t.Errorf("item has an empty title or question: %+v", items[0])
	}
	if items[0].Severity != "CRITICAL" {
		t.Errorf("severity 상 became %q", items[0].Severity)
	}
}
