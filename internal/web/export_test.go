package web

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/phpdave11/gofpdf"
)

func TestKoreanPDF(t *testing.T) {
	font := findKoreanFont()
	if font == "" {
		t.Skip("Korean font not installed")
	}
	pdf := gofpdf.New("P", "mm", "A4", filepath.Dir(font))
	pdf.AddUTF8Font("kr", "", filepath.Base(font))
	pdf.AddPage()
	pdf.SetFont("kr", "", 12)
	pdf.MultiCell(0, 6, "SecCheck 보안성 심의 결과", "", "L", false)
	var out bytes.Buffer
	if err := pdf.Output(&out); err != nil {
		t.Fatalf("render PDF: %v", err)
	}
	if out.Len() < 100 {
		t.Fatalf("PDF is unexpectedly small: %d", out.Len())
	}
}
