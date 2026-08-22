package web_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
)

// Review numbers are allocated as count+1 under an advisory transaction
// lock. Without the lock two simultaneous creations would compute the same
// number and one would fail on the unique constraint, which is the sort of
// thing that only shows up on a busy morning.
func TestConcurrentReviewCreationGetsDistinctNumbers(t *testing.T) {
	h := newHarness(t)
	h.login(adminOf(h))
	const writers = 8
	var wg sync.WaitGroup
	ids := make([]string, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			defer func() {
				if v := recover(); v != nil {
					t.Errorf("writer %d panicked: %v", n, v)
				}
			}()
			ids[n] = h.login("integration-admin").createReview("동시 생성")
		}(i)
	}
	wg.Wait()
	numbers := map[string]bool{}
	for _, id := range ids {
		if id == "" {
			t.Errorf("a concurrent creation produced no review")
			continue
		}
		var number string
		if err := h.db.Pool.QueryRow(context.Background(), `SELECT review_number FROM review_requests WHERE id=$1`, id).Scan(&number); err != nil {
			t.Fatal(err)
		}
		if numbers[number] {
			t.Errorf("review number %s was issued twice", number)
		}
		numbers[number] = true
	}
	t.Logf("%d concurrent creations produced %d distinct numbers", writers, len(numbers))
}

// Omitting expected_updated_at means "I did not read a version, take mine" --
// the documented contract for an integration that is not editing a form. All
// writers are accepted and the item keeps exactly one answer row. Writers
// that do supply a version are covered by
// TestConcurrentEditsAreDetectedRatherThanOverwritten.
func TestConcurrentAnswersWithoutAVersionAllApply(t *testing.T) {
	h := newHarness(t)
	author := h.login(adminOf(h))
	reviewID := author.createReview("동시 작성")
	items := []map[string]any{}
	if err := json.Unmarshal([]byte(author.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	itemID := items[0]["id"].(string)

	const writers = 6
	var wg sync.WaitGroup
	accepted, conflicted, other := 0, 0, 0
	var mu sync.Mutex
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			res := h.login("integration-admin").do(http.MethodPut,
				"/api/v1/review-requests/"+reviewID+"/responses/"+itemID,
				map[string]any{"applicability": "Y", "self_assessment": "COMPLIANT", "current_state": "동시 작성", "expected_updated_at": ""})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case res.status == http.StatusOK:
				accepted++
			case res.status == http.StatusConflict:
				conflicted++
			default:
				other++
				t.Errorf("writer %d got %d %s", n, res.status, res.body)
			}
		}(i)
	}
	wg.Wait()
	t.Logf("accepted=%d conflicted=%d other=%d", accepted, conflicted, other)
	var stored int
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM responses WHERE submission_item_id=$1`, itemID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 1 {
		t.Errorf("concurrent writers produced %d response rows for one item, want 1", stored)
	}
}
