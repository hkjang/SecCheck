package store_test

import (
	"context"
	"testing"

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
