package store

import (
	"encoding/json"
	"testing"
)

func TestEmbeddedDefaultChecklists(t *testing.T) {
	var checklists []DefaultChecklist
	if err := json.Unmarshal(embeddedDefaultChecklists, &checklists); err != nil {
		t.Fatal(err)
	}
	if len(checklists) != 5 {
		t.Fatalf("got %d embedded templates, want 5", len(checklists))
	}
	total := 0
	for _, checklist := range checklists {
		if checklist.Name == "" || checklist.Category == "" || checklist.Version == "" || len(checklist.Items) == 0 {
			t.Fatalf("invalid embedded checklist: %+v", checklist)
		}
		total += len(checklist.Items)
	}
	if total != 210 {
		t.Fatalf("got %d embedded items, want 210", total)
	}
}
