package web

import (
	"bytes"
	"testing"
)

func matches(detected, ext string, body []byte) bool {
	prefix := body
	if len(prefix) > 512 {
		prefix = prefix[:512]
	}
	return mimeMatchesExtension(detected, ext, bytes.NewReader(body), int64(len(body)), prefix)
}

func TestMimeMatchesExtensionNormalizesParameters(t *testing.T) {
	t.Parallel()

	if !matches("text/plain; charset=utf-8", "json", []byte(`{"valid":true}`)) {
		t.Fatal("valid JSON detected with a charset parameter must be accepted")
	}
	if !matches("text/plain; charset=utf-8", "txt", []byte("plain text")) {
		t.Fatal("plain text detected with a charset parameter must be accepted")
	}
	if matches("text/plain; charset=utf-8", "json", []byte("not-json")) {
		t.Fatal("a .json extension must not bypass JSON content validation")
	}
}

func TestJSONValidationRejectsTrailingContent(t *testing.T) {
	t.Parallel()

	if !matches("application/json", "json", []byte(`  {"a":[1,2,3]}  `)) {
		t.Error("surrounding whitespace must not invalidate a document")
	}
	for _, body := range []string{`{"a":1} {"b":2}`, `{"a":1} trailing`, `{"a":1`, ``} {
		if matches("application/json", "json", []byte(body)) {
			t.Errorf("%q was accepted as a single JSON document", body)
		}
	}
}

func TestOfficeAndLegacyExcelMagicIsChecked(t *testing.T) {
	t.Parallel()

	if matches("application/zip", "xlsx", []byte("PK\x03\x04 but not a workbook")) {
		t.Error("a bare zip must not pass as xlsx")
	}
	legacy := append([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, bytes.Repeat([]byte{0}, 32)...)
	if !matches("application/octet-stream", "xls", legacy) {
		t.Error("a real OLE compound file must be accepted for xls")
	}
	if matches("application/octet-stream", "xls", []byte("not an OLE file at all")) {
		t.Error("an xls extension must not bypass the OLE magic check")
	}
}

func TestScanBlockMessageCoversEveryNonClearedState(t *testing.T) {
	t.Parallel()

	for _, status := range []string{scanPending, scanInfected, scanError} {
		if scanBlockMessage(status) == "" {
			t.Errorf("no message for scan status %s", status)
		}
	}
}
