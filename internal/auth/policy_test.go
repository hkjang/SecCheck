package auth

import (
	"encoding/json"
	"testing"
)

func parsePolicy(t *testing.T, raw string) SecurityPolicy {
	t.Helper()
	var c securitySettings
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	return c.policy()
}

func TestPolicyFallsBackToSafeDefaults(t *testing.T) {
	want := SecurityPolicy{LoginRateLimitPerMinute: 30, MaxLoginFailures: 5, LockoutMinutes: 15}
	if got := parsePolicy(t, `{}`); got != want {
		t.Fatalf("settings without the policy keys = %+v, want %+v", got, want)
	}
	if got := parsePolicy(t, `{"login_rate_limit_per_minute":900,"max_login_failures":500,"lockout_minutes":0,"idle_timeout_minutes":-1}`); got != want {
		t.Fatalf("out-of-range settings = %+v, want %+v", got, want)
	}
}

func TestPolicyKeepsLockoutDisabledWhenChosen(t *testing.T) {
	got := parsePolicy(t, `{"login_rate_limit_per_minute":45,"max_login_failures":0,"lockout_minutes":60,"idle_timeout_minutes":30}`)
	if got.MaxLoginFailures != 0 {
		t.Fatalf("max_login_failures = %d, want 0 so administrators can turn lockout off", got.MaxLoginFailures)
	}
	if got.LoginRateLimitPerMinute != 45 || got.LockoutMinutes != 60 || got.IdleTimeoutMinutes != 30 {
		t.Fatalf("valid settings were rewritten: %+v", got)
	}
}
