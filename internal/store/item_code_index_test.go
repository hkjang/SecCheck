package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hkjang/SecCheck/internal/testdb"
)

// "How was this control judged before" is asked from every item panel: once
// for the same service's earlier reviews and once for every other service's.
// Both find items by their code across every submission ever taken, and the
// table grows by a hundred and thirty rows for every review the installation
// creates. With no index on the code, each panel read the whole table.
func TestTheEarlierVerdictLookupHasAnIndexOnTheItemCode(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	// pg_index rather than the pg_indexes view: the view renders definitions
	// for every schema on the server, and this suite drops schemas as it goes.
	var column string
	var partial bool
	if err := db.Pool.QueryRow(ctx, `SELECT a.attname,i.indpred IS NOT NULL
                FROM pg_index i
                JOIN pg_class c ON c.oid=i.indrelid
                JOIN pg_class ic ON ic.oid=i.indexrelid
                JOIN pg_namespace n ON n.oid=c.relnamespace
                JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=i.indkey[0]
                WHERE n.nspname=current_schema() AND c.relname='submission_items' AND ic.relname='idx_submission_items_code'`).Scan(&column, &partial); err != nil {
		t.Fatalf("the item-code lookup behind earlier verdicts has no index: %v", err)
	}
	if column != "item_code" {
		t.Errorf("the index leads with %s, not the column the lookup filters by", column)
	}
	if partial {
		t.Error("the index is conditional, so a lookup over every submission cannot rely on it")
	}

	// An empty table is always cheapest to scan, so the plan is asked for with
	// sequential scans disabled: what this proves is that the index covers the
	// predicate the query actually uses.
	if _, err := db.Pool.Exec(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Pool.Query(ctx, `EXPLAIN (COSTS OFF) SELECT si.id FROM submission_items si WHERE si.item_code='1.1'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	plan := ""
	for rows.Next() {
		var line string
		if rows.Scan(&line) == nil {
			plan += line + "\n"
		}
	}
	if !strings.Contains(plan, "idx_submission_items_code") {
		t.Errorf("looking an item up by its code does not use the index:\n%s", plan)
	}
}
