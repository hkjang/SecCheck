package web_test

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"
)

// poisonedWorkbook is a valid-looking .xlsx whose only cell points at shared
// string -1, with a shared-string table large enough that excelize spools it
// to a temporary file instead of memory. That is the reading path of
// GO-2026-6452 (CVE-2026-59162): the in-memory lookup checked both bounds from
// v2.11.0, the spooled one only the upper bound until upstream commit
// f98df08, so a spreadsheet an administrator was handed could take the import
// request down with an index-out-of-range panic.
func poisonedWorkbook(t *testing.T) string {
	t.Helper()
	f := excelize.NewFile()
	if err := f.SetCellValue("Sheet1", "A1", "항목코드"); err != nil {
		t.Fatal(err)
	}
	var clean bytes.Buffer
	if err := f.Write(&clean); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(clean.Bytes()), int64(clean.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	rewrote := 0
	for _, entry := range zr.File {
		rc, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		switch entry.Name {
		case "xl/worksheets/sheet1.xml":
			if !strings.Contains(string(body), "<v>0</v>") {
				t.Fatalf("sheet does not carry the shared-string cell: %s", body)
			}
			body = []byte(strings.Replace(string(body), "<v>0</v>", "<v>-1</v>", 1))
			rewrote++
		case "xl/sharedStrings.xml":
			// Past excelize's UnzipXMLSizeLimit (16 MiB) the table is read
			// from disk; the padding deflates to a few kilobytes.
			padding := "<si><t>" + strings.Repeat("x", 17<<20) + "</t></si></sst>"
			body = []byte(strings.Replace(string(body), "</sst>", padding, 1))
			rewrote++
		}
		w, err := zw.Create(entry.Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if rewrote != 2 {
		t.Fatalf("rewrote %d parts of the workbook, want the sheet and the shared strings", rewrote)
	}
	return out.String()
}

// A hostile workbook is a bad upload, not a crash: the import endpoints must
// answer with a client error (or an empty preview), never reach the panic
// handler that turns a runtime error into INTERNAL_ERROR.
func TestAHostileWorkbookIsRejectedRatherThanCrashingTheImport(t *testing.T) {
	h := newHarness(t)
	h.user("hostile-importer", "TEMPLATE_ADMIN")
	admin := h.login("hostile-importer")
	workbook := poisonedWorkbook(t)

	for _, path := range []string{"/api/v1/templates/import/preview", "/api/v1/templates/import"} {
		resp := admin.upload(path, "hostile.xlsx", workbook)
		if resp.status >= 500 || resp.errorCode() == "INTERNAL_ERROR" {
			t.Fatalf("%s answered %d %s to a workbook with a negative shared-string index; the import must reject it, not panic", path, resp.status, resp.body)
		}
		if resp.status != http.StatusOK && resp.status != http.StatusUnprocessableEntity {
			t.Errorf("%s answered %d %s, want 200 (empty preview) or 422 (rejected)", path, resp.status, resp.body)
		}
	}
}
