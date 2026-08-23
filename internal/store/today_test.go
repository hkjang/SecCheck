package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/hkjang/SecCheck/internal/testdb"
)

// Whether a follow-up has run out is a question about the calendar the
// installation displays, not about the container's clock. display_today()
// answers it in the configured zone; current_date, which every one of those
// comparisons used to use, answers it in UTC.
func TestTodayFollowsTheDisplayTimezone(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	setZone := func(zone string) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, `UPDATE settings SET value_json = jsonb_set(value_json,'{timezone}',to_jsonb($1::text)) WHERE key='general'`, zone); err != nil {
			t.Fatal(err)
		}
	}
	today := func(zone string) string {
		t.Helper()
		setZone(zone)
		var day string
		if err := db.Pool.QueryRow(ctx, `SELECT display_today()::text`).Scan(&day); err != nil {
			t.Fatalf("display_today() with zone %q: %v", zone, err)
		}
		return day
	}

	// The two zones are 25 hours apart, so their calendars never agree.
	if east, west := today("Pacific/Kiritimati"), today("Pacific/Midway"); east == west {
		t.Errorf("both sides of the date line reported the same day (%s) -- the zone is being ignored", east)
	}

	setZone("Asia/Seoul")
	var matchesSeoul bool
	if err := db.Pool.QueryRow(ctx, `SELECT display_today() = (now() AT TIME ZONE 'Asia/Seoul')::date`).Scan(&matchesSeoul); err != nil {
		t.Fatal(err)
	}
	if !matchesSeoul {
		t.Error("display_today() did not match the configured Seoul date")
	}

	// A zone nobody can parse must not take down the queries it appears in.
	setZone("Mars/Olympus")
	var fallsBackToUTC bool
	if err := db.Pool.QueryRow(ctx, `SELECT display_today() = (now() AT TIME ZONE 'UTC')::date`).Scan(&fallsBackToUTC); err != nil {
		t.Fatalf("an unparseable zone broke the query: %v", err)
	}
	if !fallsBackToUTC {
		t.Error("an unparseable zone should fall back to UTC")
	}
}

// A period filter starts where the day starts for the reader. Comparing a
// timestamptz against a bare date starts it at midnight UTC instead, which
// shifts every boundary in every report by the zone's offset.
func TestDayStartFollowsTheDisplayTimezone(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	setZone := func(zone string) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, `UPDATE settings SET value_json = jsonb_set(value_json,'{timezone}',to_jsonb($1::text)) WHERE key='general'`, zone); err != nil {
			t.Fatal(err)
		}
	}
	start := func(zone, day string) time.Time {
		t.Helper()
		setZone(zone)
		var at time.Time
		if err := db.Pool.QueryRow(ctx, `SELECT display_day_start($1::date)`, day).Scan(&at); err != nil {
			t.Fatalf("display_day_start in %s: %v", zone, err)
		}
		return at
	}

	seoul := start("Asia/Seoul", "2026-03-05")
	utc := start("UTC", "2026-03-05")
	if diff := utc.Sub(seoul); diff != 9*time.Hour {
		t.Errorf("the Seoul day starts %v before the UTC day, want 9h", diff)
	}
	// A zone with daylight saving moves the boundary with the calendar, which
	// is why the day is resolved per date rather than by a fixed offset.
	winter := start("America/New_York", "2026-01-15")
	summer := start("America/New_York", "2026-07-15")
	if winter.UTC().Hour() != 5 || summer.UTC().Hour() != 4 {
		t.Errorf("daylight saving was not applied: winter=%s summer=%s", winter.UTC(), summer.UTC())
	}

	setZone("Mars/Olympus")
	var fallsBackToUTC bool
	if err := db.Pool.QueryRow(ctx, `SELECT display_day_start('2026-03-05'::date) = '2026-03-05 00:00+00'::timestamptz`).Scan(&fallsBackToUTC); err != nil {
		t.Fatalf("an unparseable zone broke the query: %v", err)
	}
	if !fallsBackToUTC {
		t.Error("an unparseable zone should fall back to UTC")
	}
}

// A timestamp shown as a day has to be turned into that day where the reader
// lives; to_char() on a timestamptz uses the session's zone instead.
func TestDisplayDateFollowsTheDisplayTimezone(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	setZone := func(zone string) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, `UPDATE settings SET value_json = jsonb_set(value_json,'{timezone}',to_jsonb($1::text)) WHERE key='general'`, zone); err != nil {
			t.Fatal(err)
		}
	}
	// Half past three in the afternoon in UTC is already the next day in Seoul.
	at := time.Date(2026, 3, 4, 15, 30, 0, 0, time.UTC)
	day := func(zone string) string {
		t.Helper()
		setZone(zone)
		var out string
		if err := db.Pool.QueryRow(ctx, `SELECT display_date($1::timestamptz)::text`, at).Scan(&out); err != nil {
			t.Fatalf("display_date in %s: %v", zone, err)
		}
		return out
	}
	if got := day("Asia/Seoul"); got != "2026-03-05" {
		t.Errorf("display_date in Seoul = %s, want 2026-03-05", got)
	}
	if got := day("UTC"); got != "2026-03-04" {
		t.Errorf("display_date in UTC = %s, want 2026-03-04", got)
	}

	setZone("Mars/Olympus")
	var fellBack string
	if err := db.Pool.QueryRow(ctx, `SELECT display_date($1::timestamptz)::text`, at).Scan(&fellBack); err != nil {
		t.Fatalf("an unparseable zone broke the query: %v", err)
	}
	if fellBack != "2026-03-04" {
		t.Errorf("an unparseable zone should fall back to UTC, got %s", fellBack)
	}
	var missing *string
	if err := db.Pool.QueryRow(ctx, `SELECT display_date(NULL)::text`).Scan(&missing); err != nil {
		t.Fatal(err)
	}
	if missing != nil {
		t.Errorf("a missing timestamp became a day: %v", *missing)
	}
}

// The driver's default pool is four connections on a small container, which
// three background workers and one long export can occupy between them. The
// service asks for headroom unless the operator has said otherwise in the DSN.
func TestThePoolHasRoomForTheWorkers(t *testing.T) {
	db := testdb.New(t)
	if got := db.Pool.Config().MaxConns; got < 10 {
		t.Errorf("the pool allows %d connections, too few for three workers and a long export", got)
	}
	if got := db.Pool.Config().MinConns; got < 1 {
		t.Errorf("the pool keeps %d connections warm, so the first request after an idle night pays for a new one", got)
	}
	if got := db.Pool.Config().ConnConfig.ConnectTimeout; got == 0 {
		t.Error("a connection attempt has no timeout, so a database that accepts but never answers hangs the request")
	}
}
