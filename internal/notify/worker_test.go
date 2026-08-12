package notify

import "testing"

func TestSanitizeHeader(t *testing.T) {
	if got := sanitizeHeader("safe\r\nBcc: attacker@example.com"); got != "safeBcc: attacker@example.com" {
		t.Fatalf("unexpected sanitized header %q", got)
	}
}
