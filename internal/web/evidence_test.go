package web

import "testing"

func TestMimeMatchesExtensionNormalizesParameters(t *testing.T) {
	t.Parallel()

	if !mimeMatchesExtension("text/plain; charset=utf-8", "json", []byte(`{"valid":true}`)) {
		t.Fatal("valid JSON detected with a charset parameter must be accepted")
	}
	if !mimeMatchesExtension("text/plain; charset=utf-8", "txt", []byte("plain text")) {
		t.Fatal("plain text detected with a charset parameter must be accepted")
	}
	if mimeMatchesExtension("text/plain; charset=utf-8", "json", []byte("not-json")) {
		t.Fatal("a .json extension must not bypass JSON content validation")
	}
}
