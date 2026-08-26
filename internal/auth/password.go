package auth

import (
	"strings"
	"unicode"
)

// PasswordMinLength is the floor. Length is the only property that reliably
// costs an attacker anything, which is why the rest of this file bans the
// handful of twelve-character passwords that cost nothing rather than
// demanding a symbol and a capital letter.
const PasswordMinLength = 12

// weakPasswords are the ones a list attack tries first. Anything shorter than
// the minimum is already refused, so only long-enough entries are worth
// carrying here.
var weakPasswords = []string{
	"password1234", "password123!", "passw0rd1234", "administrator", "admin1234567",
	"qwerty123456", "qwertyuiop12", "1q2w3e4r5t6y", "1qaz2wsx3edc", "zaq12wsxcde3",
	"123456789012", "1234567890ab", "abcd12345678", "letmein12345", "welcome12345",
	"iloveyou1234", "security1234", "changeme1234", "temppassword", "temp12345678",
	"companyname1", "korea1234567", "seoul1234567", "seccheck1234", "test12345678",
}

// PasswordProblem reports why a password must not be accepted, in the words the
// person choosing it needs to hear. It is deliberately a small set of refusals:
// a policy that demands one of each character class pushes people towards
// "Password1!" and the twelve-character floor does more good than that ever
// did. What it does refuse is the passwords that are guessed first -- one
// character repeated, a walk along the keyboard or the number row, the name of
// this service, and the account's own username.
func PasswordProblem(password, username string) string {
	trimmed := strings.TrimSpace(password)
	if len([]rune(trimmed)) < PasswordMinLength {
		return "비밀번호는 12자 이상이어야 합니다."
	}
	if trimmed != password {
		return "비밀번호의 앞뒤 공백은 사용할 수 없습니다."
	}
	lower := strings.ToLower(password)
	for _, weak := range weakPasswords {
		// A well-known password with a couple of characters bolted on is the
		// same password. Buried inside something much longer it is not: a
		// passphrase that happens to contain one of these words is still a
		// passphrase.
		if strings.Contains(lower, weak) && len(lower) <= len(weak)+3 {
			return "너무 흔한 비밀번호입니다. 추측하기 어려운 문구로 바꾸세요."
		}
	}
	if user := strings.ToLower(strings.TrimSpace(username)); len(user) >= 3 && strings.Contains(lower, user) {
		return "비밀번호에 계정 아이디를 넣을 수 없습니다."
	}
	if strings.Contains(lower, "seccheck") {
		return "비밀번호에 서비스 이름을 넣을 수 없습니다."
	}
	if singleRune(password) {
		return "같은 문자만 반복한 비밀번호는 사용할 수 없습니다."
	}
	if runOfConsecutive(lower) >= PasswordMinLength {
		return "연속된 문자·숫자만으로 된 비밀번호는 사용할 수 없습니다."
	}
	return ""
}

func singleRune(password string) bool {
	runes := []rune(password)
	for _, r := range runes[1:] {
		if r != runes[0] {
			return false
		}
	}
	return len(runes) > 0
}

// runOfConsecutive measures the longest ascending or descending run of
// neighbouring characters -- 123456789012 and abcdefghijkl are both one walk.
func runOfConsecutive(password string) int {
	runes := []rune(password)
	longest, run, direction := 1, 1, 0
	for i := 1; i < len(runes); i++ {
		step := int(runes[i]) - int(runes[i-1])
		if (step == 1 || step == -1) && (direction == 0 || direction == step) && (unicode.IsLetter(runes[i]) || unicode.IsDigit(runes[i])) {
			direction, run = step, run+1
		} else {
			direction, run = 0, 1
			if step == 1 || step == -1 {
				direction, run = step, 2
			}
		}
		if run > longest {
			longest = run
		}
	}
	return longest
}
