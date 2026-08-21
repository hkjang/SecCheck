package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/cryptox"
)

// RFC 6238 with the parameters every authenticator app defaults to: SHA-1,
// six digits and a thirty second step. Implemented on the standard library so
// an offline deployment gains no new dependency.
const (
	totpDigits = 6
	totpPeriod = 30 * time.Second
	// One step either side absorbs ordinary clock drift between the phone and
	// the server without widening the window enough to matter.
	totpSkewSteps = 1
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh 160-bit secret in the base32 form that
// authenticator apps accept for manual entry.
func NewTOTPSecret() (string, error) {
	raw, err := cryptox.RandomBytes(20)
	if err != nil {
		return "", err
	}
	return totpEncoding.EncodeToString(raw), nil
}

// TOTPURI builds the otpauth:// enrolment URI. It is shown as text and as a
// copyable secret rather than a QR image, so no image encoder is needed.
func TOTPURI(issuer, account, secret string) string {
	q := url.Values{
		"secret":    {secret},
		"issuer":    {issuer},
		"algorithm": {"SHA1"},
		"digits":    {fmt.Sprint(totpDigits)},
		"period":    {fmt.Sprint(int(totpPeriod.Seconds()))},
	}
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + q.Encode()
}

// FormatTOTPSecret groups the secret into blocks of four so it can be typed by
// hand without losing your place.
func FormatTOTPSecret(secret string) string {
	var parts []string
	for i := 0; i < len(secret); i += 4 {
		parts = append(parts, secret[i:min(i+4, len(secret))])
	}
	return strings.Join(parts, " ")
}

// VerifyTOTP checks a submitted code against the secret, accepting the
// adjacent steps. Comparison is constant time.
func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(strings.ReplaceAll(code, " ", ""))
	if len(code) != totpDigits {
		return false
	}
	key, err := totpEncoding.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil || len(key) == 0 {
		return false
	}
	counter := now.Unix() / int64(totpPeriod.Seconds())
	for step := -totpSkewSteps; step <= totpSkewSteps; step++ {
		if subtle.ConstantTimeCompare([]byte(totpAt(key, counter+int64(step))), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func totpAt(key []byte, counter int64) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, value%1_000_000)
}
