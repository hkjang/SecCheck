package store_test

import (
	"context"
	"strings"
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
	var definition string
	if err := db.Pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE tablename='evidences' AND indexname='idx_evidences_item_all'`).Scan(&definition); err != nil {
		t.Fatalf("evidence_touched_at has no index that includes deleted rows: %v", err)
	}
	if strings.Contains(definition, "WHERE") {
		t.Errorf("the index is conditional, so the lookup that reads deleted rows still cannot use it: %s", definition)
	}
	if !strings.Contains(definition, "submission_item_id") {
		t.Errorf("the index is not on the column the lookup filters by: %s", definition)
	}

	// And the function still answers the question it exists to answer.
	var plan string
	if err := db.Pool.QueryRow(ctx, `EXPLAIN (COSTS OFF) SELECT evidence_touched_at('nobody')`).Scan(&plan); err != nil {
		t.Fatalf("evidence_touched_at is not callable: %v", err)
	}
}
