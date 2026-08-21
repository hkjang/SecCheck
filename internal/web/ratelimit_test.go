package web

import (
	"testing"
	"time"
)

func TestRateLimiterEnforcesPerKeyBudget(t *testing.T) {
	l := newRateLimiter()
	for i := 0; i < 3; i++ {
		if !l.allow("10.0.0.1", 3) {
			t.Fatalf("request %d was rejected inside the budget", i+1)
		}
	}
	if l.allow("10.0.0.1", 3) {
		t.Fatal("fourth request was allowed past the budget")
	}
	if !l.allow("10.0.0.2", 3) {
		t.Fatal("a different source address must have its own budget")
	}
}

func TestRateLimiterEvictsExpiredWindows(t *testing.T) {
	l := newRateLimiter()
	for i := 0; i < 100; i++ {
		l.allow(string(rune('a'+i%26))+string(rune('a'+i/26)), 10)
	}
	stale := time.Now().Add(-2 * time.Minute)
	for _, e := range l.entries {
		e.window = stale
	}
	l.sweptAt = stale
	l.allow("10.0.0.1", 10)
	if len(l.entries) != 1 {
		t.Fatalf("expired windows were kept: %d entries remain", len(l.entries))
	}
}

func TestRateLimiterCountsOnlyRecordedEvents(t *testing.T) {
	l := newRateLimiter()
	for i := 0; i < 50; i++ {
		if l.blocked("10.0.0.1", 3) {
			t.Fatalf("peek %d blocked a key that never recorded an event", i+1)
		}
	}
	for i := 0; i < 3; i++ {
		l.record("10.0.0.1")
	}
	if !l.blocked("10.0.0.1", 3) {
		t.Fatal("the key spent its budget but is not blocked")
	}
	if l.blocked("10.0.0.2", 3) {
		t.Fatal("a different source address must have its own budget")
	}
}
