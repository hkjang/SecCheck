package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// The RFC 6238 SHA-1 reference vectors, with the published secret "12345678901234567890".
func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, tc := range []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	} {
		at := time.Unix(tc.unix, 0).UTC()
		if !VerifyTOTP(secret, tc.code, at) {
			t.Errorf("code %s was rejected at %d", tc.code, tc.unix)
		}
	}
}

func TestTOTPAcceptsAdjacentStepsAndRejectsFurtherDrift(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	current := totpAt(key, now.Unix()/30)
	for _, offset := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		if !VerifyTOTP(secret, current, now.Add(offset)) {
			t.Errorf("a code %v out of step was rejected", offset)
		}
	}
	for _, offset := range []time.Duration{-90 * time.Second, 90 * time.Second} {
		if VerifyTOTP(secret, current, now.Add(offset)) {
			t.Errorf("a code %v out of step was accepted", offset)
		}
	}
}

func TestTOTPRejectsMalformedInput(t *testing.T) {
	secret, _ := NewTOTPSecret()
	now := time.Now()
	for _, code := range []string{"", "12345", "1234567", "abcdef", "  "} {
		if VerifyTOTP(secret, code, now) {
			t.Errorf("malformed code %q was accepted", code)
		}
	}
	if VerifyTOTP("not base32!!", "123456", now) {
		t.Error("an unusable secret must never verify")
	}
}

func TestTOTPEnrolmentHelpers(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 32 {
		t.Fatalf("secret length = %d, want 32 base32 characters for 160 bits", len(secret))
	}
	uri := TOTPURI("SecCheck", "admin", secret)
	if !strings.HasPrefix(uri, "otpauth://totp/SecCheck:admin?") || !strings.Contains(uri, "secret="+secret) {
		t.Fatalf("unexpected enrolment URI: %s", uri)
	}
	if formatted := FormatTOTPSecret(secret); strings.ReplaceAll(formatted, " ", "") != secret {
		t.Fatalf("grouping changed the secret: %s", formatted)
	}
}
