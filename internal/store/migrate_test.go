package store_test

import (
	"context"
	"testing"

	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/testdb"
)

func TestMigrationFilesAreOrderedAndUnique(t *testing.T) {
	files, err := store.MigrationFiles()
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	if len(files) < 2 {
		t.Fatalf("expected the baseline plus at least one migration, got %d", len(files))
	}
	if files[0].Version != 1 {
		t.Errorf("the baseline must stay version 1, got %d", files[0].Version)
	}
	for i := 1; i < len(files); i++ {
		if files[i].Version <= files[i-1].Version {
			t.Errorf("%s is not ordered after %s", files[i].Name, files[i-1].Name)
		}
	}
}

func TestMigrateIsIdempotentAndRecordsEveryVersion(t *testing.T) {
	s := testdb.New(t)
	ctx := context.Background()
	files, err := store.MigrationFiles()
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	newest := files[len(files)-1].Version
	if got := s.SchemaVersion(ctx); got != newest {
		t.Fatalf("schema version = %d, want %d", got, newest)
	}
	// A second run must be a no-op rather than an error.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var applied int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if applied != len(files) {
		t.Errorf("recorded %d versions, want %d", applied, len(files))
	}
}

// An installation created before numbered migrations existed already has the
// baseline applied and only version 1 recorded. Upgrading must apply the newer
// files and nothing else.
func TestMigrateUpgradesALegacyInstallation(t *testing.T) {
	s := testdb.New(t)
	ctx := context.Background()
	files, err := store.MigrationFiles()
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	if _, err = s.Pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version > 1`); err != nil {
		t.Fatalf("simulate legacy state: %v", err)
	}
	for _, name := range []string{"idx_submission_items_submission", "idx_notifications_recipient_unread"} {
		if _, err = s.Pool.Exec(ctx, `DROP INDEX IF EXISTS `+name); err != nil {
			t.Fatalf("drop %s: %v", name, err)
		}
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if got := s.SchemaVersion(ctx); got != files[len(files)-1].Version {
		t.Fatalf("schema version after upgrade = %d, want %d", got, files[len(files)-1].Version)
	}
	var present int
	if err = s.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE schemaname=current_schema() AND indexname IN ('idx_submission_items_submission','idx_notifications_recipient_unread')`).Scan(&present); err != nil {
		t.Fatalf("inspect indexes: %v", err)
	}
	if present != 2 {
		t.Errorf("the upgrade recreated %d of 2 indexes", present)
	}
}

func TestHotPathForeignKeysAreIndexed(t *testing.T) {
	s := testdb.New(t)
	// Every foreign key that the checklist, evidence and notification screens
	// join through needs a leading index, or the query degrades to a scan.
	rows, err := s.Pool.Query(context.Background(), `
                SELECT c.conrelid::regclass::text, a.attname
                FROM pg_constraint c
                JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=c.conkey[1]
                WHERE c.contype='f' AND array_length(c.conkey,1)=1
                  AND connamespace=current_schema()::regnamespace
                  AND NOT EXISTS (
                    SELECT 1 FROM pg_index i
                    WHERE i.indrelid=c.conrelid AND i.indkey[0]=c.conkey[1])`)
	if err != nil {
		t.Fatalf("inspect foreign keys: %v", err)
	}
	defer rows.Close()
	// Reference and ownership columns that are only ever read through the row
	// itself do not need their own index.
	allowed := map[string]bool{
		"users.id": true, "checklist_items.section_id": true, "responses.assigned_to": true,
		"responses.updated_by": true, "review_results.reviewer_id": true, "comments.author_id": true,
		"approvals.approver_id": true, "audit_logs.user_id": true, "settings.updated_by": true,
		"submissions.submitted_by": true, "evidences.uploaded_by": true, "evidences.key_owner_id": true,
		"evidence_versions.uploaded_by": true, "evidence_versions.key_owner_id": true,
		"change_requests.requester_id": true, "change_requests.assignee_id": true,
		"template_changes.changed_by": true, "rule_overrides.changed_by": true,
		"rule_overrides.source_item_id": true, "checklist_templates.owner_id": true,
		"checklist_versions.published_by": true, "review_requests.builder_id": true,
		"review_requests.developer_id": true, "review_requests.operator_id": true,
		"rule_overrides.submission_id": true, "security_controls.owner_id": true,
		"checklist_templates.created_by": true, "checklist_versions.created_by": true,
	}
	var missing []string
	for rows.Next() {
		var table, column string
		if err = rows.Scan(&table, &column); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if key := table + "." + column; !allowed[key] {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Errorf("foreign keys without a leading index: %v", missing)
	}
}

// The text filters all use ILIKE '%term%'. Where pg_trgm is available the
// migration must have created the GIN indexes that make those index scans;
// where it is not, the installation must still be fully migrated.
func TestTrigramIndexesExistWhenTheExtensionDoes(t *testing.T) {
	s := testdb.New(t)
	ctx := context.Background()
	var hasExtension bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname='pg_trgm')`).Scan(&hasExtension); err != nil {
		t.Fatal(err)
	}
	if !hasExtension {
		t.Skip("pg_trgm is not installed on this server; the migration degraded gracefully")
	}
	want := []string{
		"idx_review_requests_service_trgm", "idx_submission_items_title_trgm",
		"idx_evidences_filename_trgm", "idx_audit_logs_user_name_trgm",
		"idx_application_logs_message_trgm",
	}
	for _, name := range want {
		var present bool
		if err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE schemaname=current_schema() AND indexname=$1)`, name).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if !present {
			t.Errorf("%s is missing", name)
		}
	}
}

func TestAuditChainCheckpointColumnsExist(t *testing.T) {
	s := testdb.New(t)
	var sequence int64
	var hash string
	if err := s.Pool.QueryRow(context.Background(), `SELECT verified_sequence,verified_hash FROM audit_chain_state WHERE id=1`).Scan(&sequence, &hash); err != nil {
		t.Fatalf("the verification checkpoint is not usable: %v", err)
	}
	if sequence != 0 || hash != "" {
		t.Errorf("a fresh installation starts unverified, got sequence=%d hash=%q", sequence, hash)
	}
}
