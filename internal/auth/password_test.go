package auth_test

import (
	"strings"
	"testing"

	"github.com/hkjang/SecCheck/internal/auth"
)

// The service asks every other team whether they have a control against weak
// passwords, and accepted twelve letters "a" for its own accounts. Length is
// the property worth insisting on; these are the twelve-character passwords
// that are worth nothing.
func TestThePasswordPolicyRefusesWhatIsGuessedFirst(t *testing.T) {
	refused := map[string]string{
		"short":                  "비밀번호는 12자 이상이어야 합니다.",
		"aaaaaaaaaaaa":           "같은 문자만 반복한 비밀번호는 사용할 수 없습니다.",
		"123456789012":           "너무 흔한 비밀번호입니다. 추측하기 어려운 문구로 바꾸세요.",
		"abcdefghijkl":           "연속된 문자·숫자만으로 된 비밀번호는 사용할 수 없습니다.",
		"Password1234":           "너무 흔한 비밀번호입니다. 추측하기 어려운 문구로 바꾸세요.",
		"password1234!":          "너무 흔한 비밀번호입니다. 추측하기 어려운 문구로 바꾸세요.",
		"seccheck-admin-2026":    "비밀번호에 서비스 이름을 넣을 수 없습니다.",
		"  spaced-out-password ": "비밀번호의 앞뒤 공백은 사용할 수 없습니다.",
	}
	for password, want := range refused {
		if got := auth.PasswordProblem(password, "hana.kim"); got != want {
			t.Errorf("%q was refused as %q, want %q", password, got, want)
		}
	}

	// The account's own name is the first thing anybody tries.
	if got := auth.PasswordProblem("hana.kim-2026-spring", "hana.kim"); !strings.Contains(got, "아이디") {
		t.Errorf("a password built from the username reads %q", got)
	}
	// A short username is not a useful thing to search for inside a password.
	if got := auth.PasswordProblem("goodenough-passphrase", "ab"); got != "" {
		t.Errorf("a two-letter username refused an unrelated password: %q", got)
	}

	// What the policy is for: ordinary long passphrases pass without being
	// told to add a capital letter and a symbol.
	// A passphrase that happens to contain a common word is still a
	// passphrase; only the word with a couple of characters bolted on is the
	// same password.
	for _, password := range []string{"올해도무사히넘어가자모두", "correct horse battery staple", "P4ssphrase-for-secchk", "행복한하루보내세요2026", "my-welcome12345-to-the-team"} {
		if got := auth.PasswordProblem(password, "hana.kim"); got != "" {
			t.Errorf("%q was refused as %q", password, got)
		}
	}
}
