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

// Two rows whose codes differ only past the fortieth character are two rows the
// database sees as one: the column stores forty. Deduplicating before that
// truncation let both land on the same stored code, and the import failed as a
// whole -- on a three hundred row workbook, with a database error and no row
// number.
func TestLongCodesThatShareTheirFirstFortyCharactersStayDistinct(t *testing.T) {
	long := "3.2.1 접근통제 정책 수립 및 이행 여부를 주기적으로 점검하고 기록한다 - "
	rows := [][]string{
		{"항목코드", "보안 요건 항목", "점검항목"},
		{long + "서버", "서버 접근통제", "서버에 대한 접근통제가 이루어지는가?"},
		{long + "네트워크", "네트워크 접근통제", "네트워크에 대한 접근통제가 이루어지는가?"},
		{long + "서버", "중복된 행", "같은 코드가 두 번 나오는 경우"},
	}
	header, mapping := detectHeaders(rows)
	items, report := parseImportRowsWithReport(rows, header, mapping, "INFRA")
	if len(items) != 3 {
		t.Fatalf("parsed %d items, want 3 (report %+v)", len(items), report)
	}
	seen := map[string]bool{}
	for _, item := range items {
		if len([]rune(item.ItemCode)) > itemFieldLimits["item_code"] {
			t.Errorf("stored code is %d characters, over the column limit: %q", len([]rune(item.ItemCode)), item.ItemCode)
		}
		if seen[item.ItemCode] {
			t.Errorf("two rows would be stored under the same code %q, which the unique index refuses", item.ItemCode)
		}
		seen[item.ItemCode] = true
	}
	if len(report.DuplicateCodes) == 0 {
		t.Error("the wizard does not warn that codes collided")
	}
}

// The dry run said what the parser would change -- twelve rows skipped, three
// codes invented -- and never which rows, so finding them meant diffing a
// three-hundred-row workbook against the created items by hand. That is the
// work the preview exists to save.
func TestTheImportPreviewNamesTheRowsItChanged(t *testing.T) {
	long := strings.Repeat("가", 400)
	rows := [][]string{
		{"항목코드", "보안요건", "점검항목", "중요도"},
		{"A-1", "정상 항목", "정상적으로 작성된 질문입니다", "상"},
		{"", "", "", ""}, // blank spacer: not reported
		{"", "표 아래 참고 문구입니다", "", ""},        // row 4: a note that becomes an item
		{"", "코드 없는 항목", "코드가 비어 있습니다", "중"}, // row 5: code invented
		{"주석", "", "", ""},              // row 6: text but nothing to make an item from
		{"A-2", long, "너무 긴 보안요건", "하"}, // row 7: shortened
	}
	header, mapping := detectHeaders(rows)
	items, report := parseImportRowsWithReport(rows, header, mapping, "DEVELOPMENT")
	if len(items) != 4 {
		t.Fatalf("parsed %d items, want 4: %+v", len(items), report)
	}
	if report.SkippedRows != 1 || len(report.SkippedRowNumbers) != 1 || report.SkippedRowNumbers[0] != 6 {
		t.Errorf("skipped rows reported as %d %v, want row 6", report.SkippedRows, report.SkippedRowNumbers)
	}
	if report.GeneratedCodes != 2 || len(report.GeneratedCodeRows) != 2 || report.GeneratedCodeRows[0] != 4 || report.GeneratedCodeRows[1] != 5 {
		t.Errorf("invented codes reported as %d %v, want rows 4 and 5", report.GeneratedCodes, report.GeneratedCodeRows)
	}
	if report.ShortenedFields != 1 || len(report.ShortenedRowNumbers) != 1 || report.ShortenedRowNumbers[0] != 7 {
		t.Errorf("shortened rows reported as %d %v, want row 7", report.ShortenedFields, report.ShortenedRowNumbers)
	}
	// The row numbers are the ones the reader sees in the spreadsheet, so they
	// count the header row too.
	for _, row := range append(append([]int{}, report.SkippedRowNumbers...), report.ShortenedRowNumbers...) {
		if row < 1 || row > len(rows) {
			t.Errorf("row %d is not a row of this sheet (1..%d)", row, len(rows))
		}
	}
}

// A workbook can be long enough that the list is no help; past the cap the
// count is the useful number and the list must not grow without bound.
func TestTheImportPreviewCapsTheRowsItLists(t *testing.T) {
	rows := [][]string{{"항목코드", "보안요건", "점검항목"}}
	for i := 0; i < reportedRows+20; i++ {
		rows = append(rows, []string{"", "", "", "버려질 메모"})
	}
	header, mapping := detectHeaders(rows)
	_, report := parseImportRowsWithReport(rows, header, mapping, "DEVELOPMENT")
	if report.SkippedRows != reportedRows+20 {
		t.Errorf("skipped %d rows, want %d", report.SkippedRows, reportedRows+20)
	}
	if len(report.SkippedRowNumbers) != reportedRows {
		t.Errorf("listed %d row numbers, want the cap of %d", len(report.SkippedRowNumbers), reportedRows)
	}
}
