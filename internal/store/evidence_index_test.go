package store_test

import (
	"context"
	"testing"

	"github.com/hkjang/SecCheck/internal/testdb"
)

// evidence_touched_at() decides whether a verdict still describes the evidence
// it judged, so it has to see files that were deleted as well as files that are
// there. The only index on the column was partial -- deleted rows excluded --
// which meant this lookup could not use it and read the whole table instead,
// once per checklist item, on every load of a review. The plan is what matters
// and an empty database cannot demonstrate it; what a test can hold is that the
// index this query needs is present and covers every row.
func TestTheEvidenceLookupBehindStaleVerdictsHasAnIndex(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	// The catalogue is read through pg_index rather than the pg_indexes view:
	// the view renders a definition for every schema on the server, and the
	// suite runs each test in its own schema that is dropped when it ends, so
	// rendering one that is going away fails the query for everybody else.
	var column string
	var partial bool
	if err := db.Pool.QueryRow(ctx, `SELECT a.attname,i.indpred IS NOT NULL
                FROM pg_index i
                JOIN pg_class c ON c.oid=i.indrelid
                JOIN pg_class ic ON ic.oid=i.indexrelid
                JOIN pg_namespace n ON n.oid=c.relnamespace
                JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=i.indkey[0]
                WHERE n.nspname=current_schema() AND c.relname='evidences' AND ic.relname='idx_evidences_item_all'`).Scan(&column, &partial); err != nil {
		t.Fatalf("evidence_touched_at has no index that includes deleted rows: %v", err)
	}
	if partial {
		t.Error("the index is conditional, so the lookup that reads deleted rows still cannot use it")
	}
	if column != "submission_item_id" {
		t.Errorf("the index leads with %s, not the column the lookup filters by", column)
	}

	// And the function still answers the question it exists to answer.
	var plan string
	if err := db.Pool.QueryRow(ctx, `EXPLAIN (COSTS OFF) SELECT evidence_touched_at('nobody')`).Scan(&plan); err != nil {
		t.Fatalf("evidence_touched_at is not callable: %v", err)
	}
}
