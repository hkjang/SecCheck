package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/testdb"
)

// Quarantine deletes a file from a checklist, which is exactly what the audit
// chain is for: when a person deletes evidence the chain says who and when. The
// scanner did the same thing and wrote only a server log, so the item quietly
// had one fewer file and the log gave no reason.
func TestQuarantineIsWrittenToTheAuditChain(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	uploader := testdb.Bootstrap(t, db, "scan-uploader")
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	reviewID, submissionID, itemID, evidenceID := store.NewID(), store.NewID(), store.NewID(), store.NewID()
	exec(`INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,exposure,status)
              VALUES($1,'SR-SCAN','s','d','WEB','NEW',$2,$2,'보안팀',$2,'INTERNAL','DRAFT')`, reviewID, uploader)
	exec(`INSERT INTO submissions(id,review_request_id,revision,status) VALUES($1,$2,1,'DRAFT')`, submissionID, reviewID)
	exec(`INSERT INTO submission_items(id,submission_id,template_name,template_version,item_code,section,category,title,question,severity,required,answer_type,evidence_required,sort_order)
              VALUES($1,$2,'기본','1.0','A-01','일반','보안','제목','질문','HIGH',true,'YNNA',true,1)`, itemID, submissionID)
	exec(`INSERT INTO evidences(id,submission_item_id,original_filename,stored_filename,mime_type,size_bytes,sha256,uploaded_by,key_owner_id,key_version)
              VALUES($1,$2,'악성.zip','stored.bin','application/zip',10,'abc123',$3,$3,1)`, evidenceID, itemID, uploader)

	worker := New(db, nil)
	if err := worker.quarantine(ctx, evidenceID, "악성.zip", "Eicar-Test-Signature FOUND"); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	var deleted bool
	if err := db.Pool.QueryRow(ctx, `SELECT deleted_at IS NOT NULL AND scan_status='INFECTED' FROM evidences WHERE id=$1`, evidenceID).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Error("the infected evidence is still attached to the checklist")
	}
	var after string
	if err := db.Pool.QueryRow(ctx, `SELECT after_value FROM audit_logs WHERE event_type='QUARANTINE_EVIDENCE' AND target_id=$1`, evidenceID).Scan(&after); err != nil {
		t.Fatalf("the quarantine left no audit event: %v", err)
	}
	if !strings.Contains(after, "Eicar-Test-Signature") {
		t.Errorf("the audit event does not say what was found: %s", after)
	}
	var told int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE recipient_id=$1 AND event_type='EVIDENCE_INFECTED'`, uploader).Scan(&told); err != nil {
		t.Fatal(err)
	}
	if told != 1 {
		t.Errorf("the uploader received %d notices about their infected file", told)
	}
}

// The uploader is not the only person a quarantine concerns. If the item was
// already judged, the verdict now rests on a file that is no longer there, and
// nothing else will ever raise that again once the review is approved.
func TestQuarantineWarnsTheReviewOwners(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	uploader := testdb.Bootstrap(t, db, "quarantine-uploader")
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	requester, reviewer := store.NewID(), store.NewID()
	exec(`INSERT INTO users(id,username,display_name,email,password_hash) VALUES($1,'q-requester','요청자','q1@example.test','x'),($2,'q-reviewer','검토자','q2@example.test','x')`, requester, reviewer)
	reviewID, submissionID, itemID, evidenceID := store.NewID(), store.NewID(), store.NewID(), store.NewID()
	exec(`INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,reviewer_id,exposure,status)
              VALUES($1,'SR-QUAR','격리 서비스','d','WEB','NEW',$2,$2,'보안팀',$3,$4,'INTERNAL','APPROVED')`, reviewID, uploader, requester, reviewer)
	exec(`INSERT INTO submissions(id,review_request_id,revision,status) VALUES($1,$2,1,'APPROVED')`, submissionID, reviewID)
	exec(`INSERT INTO submission_items(id,submission_id,template_name,template_version,item_code,section,category,title,question,severity,required,answer_type,evidence_required,sort_order)
              VALUES($1,$2,'기본','1.0','B-02','일반','보안','제목','질문','HIGH',true,'YNNA',true,1)`, itemID, submissionID)
	exec(`INSERT INTO review_results(id,submission_item_id,reviewer_id,result,opinion) VALUES($1,$2,$3,'COMPLIANT','증적 확인함')`, store.NewID(), itemID, reviewer)
	exec(`INSERT INTO evidences(id,submission_item_id,original_filename,stored_filename,mime_type,size_bytes,sha256,uploaded_by,key_owner_id,key_version)
              VALUES($1,$2,'감염.zip','stored.bin','application/zip',10,'abc123',$3,$3,1)`, evidenceID, itemID, uploader)

	if err := New(db, nil).quarantine(ctx, evidenceID, "감염.zip", "Eicar-Test-Signature FOUND"); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	notice := func(userID string) (string, string) {
		t.Helper()
		var body, item string
		if err := db.Pool.QueryRow(ctx, `SELECT body,COALESCE(item_id,'') FROM notifications WHERE recipient_id=$1 AND event_type='EVIDENCE_INFECTED'`, userID).Scan(&body, &item); err != nil {
			t.Fatalf("no quarantine notice for %s: %v", userID, err)
		}
		return body, item
	}
	// The requester owns re-attaching the evidence, the reviewer owns the
	// verdict that rested on it, and both notices open the item itself.
	for _, who := range []string{requester, reviewer} {
		body, item := notice(who)
		if item != itemID {
			t.Errorf("the notice for %s points at %q, want the item", who, item)
		}
		if !strings.Contains(body, "B-02") || !strings.Contains(body, "감염.zip") {
			t.Errorf("the notice does not say which item or file: %s", body)
		}
		if !strings.Contains(body, "이미 판정된") {
			t.Errorf("the notice does not say the verdict lost its basis: %s", body)
		}
	}
	// The uploader still hears about it, once.
	var uploaderNotices int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE recipient_id=$1 AND event_type='EVIDENCE_INFECTED'`, uploader).Scan(&uploaderNotices); err != nil {
		t.Fatal(err)
	}
	if uploaderNotices != 1 {
		t.Errorf("the uploader received %d notices, want 1", uploaderNotices)
	}
}
