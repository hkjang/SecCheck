// Package maintenance keeps the operational tables bounded. SecCheck runs
// offline for years at a time, so expired authentication state, finished jobs
// and application logs have to be reclaimed by the service itself rather than
// by an external cron job.
package maintenance

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/vault"
)

// Deletes run in bounded batches so a first sweep over a long-neglected
// installation never holds a single long transaction.
// StalledReviewDays is how long a review may sit without moving before the
// service treats it as stuck.
const StalledReviewDays = 3

// orphanScanLimit bounds the directory walk: past this many files the count is
// a signal rather than an inventory, and the sweep has other work to do.
const orphanScanLimit = 20000

// StalledStatuses are the states in which a review is waiting on a person
// rather than on work in progress. Sharing the days but not the states left
// exactly the discrepancy the shared constant exists to prevent: the sweep
// chased reviews waiting for a final signature and the dashboard did not count
// them, so the screen said 2 while the mail chased 5 -- and the reviews it
// left out were the ones at the last gate before the service opens.
var StalledStatuses = []string{"SUBMITTED", "RESUBMITTED", "REVIEWING", "APPROVAL_PENDING"}

const (
	batchSize     = 5000
	maxBatches    = 40
	interval      = time.Hour
	startupDelay  = time.Minute
	completedJobs = 7
	failedJobs    = 90
	// The queue workers poll every five seconds. A job that has been due for
	// this long is not queued behind work, it is not being picked up at all.
	stalledAfter  = 15 * time.Minute
	stallReminder = 6 * time.Hour
	// A review that has not moved in this long is waiting on a person, not on
	// work in progress, and the same person is not told again for this long.
	// Exported because the dashboard counts the same set: a screen that says
	// "2 stalled" while the mail chases 5 is two answers to one question.
	stalledReviewDays = StalledReviewDays
	// How close a planned open date has to be before the people who can still
	// finish the review are told, and how long before they are told again.
	openDateWarningDays = 3
	// Room below either of these is worth waking somebody for: proportionally
	// nearly full, or absolutely close enough that a few uploads finish it.
	lowStorageRatio = 0.10
	lowStorageBytes = 2 << 30
	// How long before an API key expires its owner is warned, and how long
	// before they are warned again.
	apiKeyWarningDays = 7
	// How long a job may hold its lock before the worker holding it is assumed
	// to be gone. Both workers use the same window when they start.
	abandonedAfter = 15 * time.Minute
	// How many stored files are read back per sweep. Small enough that an
	// hourly check is invisible next to ordinary uploads, large enough that a
	// volume of any size comes round within days.
	evidenceSamplePerSweep = 20
)

type Worker struct {
	Store *store.Store
	Vault *vault.Vault
}

func New(s *store.Store, v *vault.Vault) *Worker { return &Worker{Store: s, Vault: v} }

func (w *Worker) Run(ctx context.Context) {
	timer := time.NewTimer(startupDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		w.Sweep(ctx)
		timer.Reset(interval)
	}
}

// Sweep reclaims every expired or over-retention row. Audit logs are never
// touched: their hash chain has to stay verifiable for the lifetime of the
// installation.
func (w *Worker) Sweep(ctx context.Context) map[string]int64 {
	retention := w.retentionDays(ctx)
	removed := map[string]int64{
		"sessions":         w.delete(ctx, `DELETE FROM sessions WHERE ctid IN (SELECT ctid FROM sessions WHERE expires_at<now() LIMIT $1)`),
		"oidc_states":      w.delete(ctx, `DELETE FROM oidc_states WHERE ctid IN (SELECT ctid FROM oidc_states WHERE expires_at<now() LIMIT $1)`),
		"jobs":             w.delete(ctx, `DELETE FROM jobs WHERE ctid IN (SELECT ctid FROM jobs WHERE (status='COMPLETED' AND updated_at<now()-make_interval(days=>$2)) OR (status='FAILED' AND updated_at<now()-make_interval(days=>$3)) LIMIT $1)`, completedJobs, failedJobs),
		"application_logs": w.delete(ctx, `DELETE FROM application_logs WHERE ctid IN (SELECT ctid FROM application_logs WHERE timestamp<now()-make_interval(days=>$2) LIMIT $1)`, retention),
		"notifications":    w.delete(ctx, `DELETE FROM notifications WHERE ctid IN (SELECT ctid FROM notifications WHERE created_at<now()-make_interval(days=>$2) LIMIT $1)`, retention),
	}
	tag, err := w.Store.Pool.Exec(ctx, `UPDATE users SET failed_login_count=0,locked_until=NULL WHERE locked_until IS NOT NULL AND locked_until<now()`)
	if err == nil {
		removed["expired_lockouts"] = tag.RowsAffected()
	}
	removed["due_reminders"] = w.remindDueChangeRequests(ctx)
	removed["follow_up_reminders"] = w.remindDueFollowUps(ctx)
	removed["stalled_reviews"] = w.remindStalledReviews(ctx)
	removed["open_date_reminders"] = w.remindApproachingOpenDates(ctx)
	removed["stall_alerts"] = w.alertStalledQueue(ctx)
	removed["failure_alerts"] = w.alertFailedJobs(ctx)
	removed["storage_alerts"] = w.alertLowStorage(ctx)
	removed["requeued_jobs"] = w.requeueAbandonedJobs(ctx)
	removed["evidence_checked"] = w.verifyEvidenceSample(ctx)
	removed["audit_chain_checked"] = w.verifyAuditChain(ctx)
	removed["api_key_reminders"] = w.remindExpiringAPIKeys(ctx)
	removed["purged_evidence_files"] = w.purgeDeletedEvidence(ctx)
	removed["orphan_evidence_files"] = w.countOrphanBlobs(ctx)
	total := int64(0)
	for name, n := range removed {
		// An orphan count is a finding, not something the sweep removed.
		if name == "orphan_evidence_files" {
			continue
		}
		total += n
	}
	if total > 0 {
		w.Store.Log(ctx, "INFO", "", "maintenance", "retention sweep completed", map[string]any{"retention_days": retention, "removed": removed})
	}
	// A completed run is recorded so that a housekeeping goroutine that has
	// died shows up as an ageing timestamp instead of as reminders that
	// quietly stopped arriving.
	summary, _ := json.Marshal(removed)
	if _, err := w.Store.Pool.Exec(ctx, `UPDATE maintenance_state SET last_run_at=now(),last_summary=$1 WHERE id=1`, summary); err != nil {
		w.Store.Log(ctx, "ERROR", "", "maintenance", "could not record the sweep", map[string]any{"error": err.Error()})
	}
	return removed
}

// verifyAuditChain proves the tamper-evidence the audit log is built on. The
// console has always been able to check it, but only when somebody remembered
// to press the button: a row edited in the database, or a restore that lost
// events, could sit undetected for as long as nobody looked. The anchor makes
// the routine check cheap -- only what was appended since the last run is
// re-hashed -- and a break is reported to administrators the same way the
// console reports it.
func (w *Worker) verifyAuditChain(ctx context.Context) int64 {
	from, previous, err := w.Store.AuditCheckpoint(ctx)
	if err != nil {
		w.Store.Log(ctx, "ERROR", "", "maintenance", "audit chain checkpoint unreadable", map[string]any{"error": err.Error()})
		return 0
	}
	result, err := w.Store.VerifyAuditChain(ctx, from, previous)
	if err != nil {
		w.Store.Log(ctx, "ERROR", "", "maintenance", "audit chain verification failed to run", map[string]any{"error": err.Error()})
		return 0
	}
	if !result.Valid {
		w.Store.Log(ctx, "ERROR", "", "audit", "audit chain verification failed", map[string]any{"event_id": result.FailedEventID, "sequence": result.FailedSequence, "reason": result.Reason, "source": "maintenance"})
		// The anchor is deliberately left where it was: moving it forward past
		// a break would declare the tampered stretch proved.
		admins, adminErr := w.uninformedAdmins(ctx, "AUDIT_CHAIN_BROKEN")
		if adminErr != nil {
			return 0
		}
		body := fmt.Sprintf("정기 점검에서 감사로그 %d번 이벤트의 무결성 검증에 실패했습니다 (%s). 데이터베이스 직접 변경 여부를 즉시 확인하세요.", result.FailedSequence, result.Reason)
		for _, admin := range admins {
			if notifyErr := w.Store.Notify(ctx, admin, "AUDIT_CHAIN_BROKEN", "감사로그 체인 검증 실패", body, "AUDIT_LOG", result.FailedEventID); notifyErr != nil {
				w.Store.Log(ctx, "ERROR", "", "audit", "could not notify an administrator of the chain break", map[string]any{"recipient": admin, "error": notifyErr.Error()})
			}
		}
		return 0
	}
	if result.Checked > 0 {
		if err = w.Store.MarkAuditChainVerified(ctx, result.HeadSequence, result.HeadHash); err != nil {
			w.Store.Log(ctx, "ERROR", "", "maintenance", "audit chain checkpoint could not be advanced", map[string]any{"error": err.Error()})
		}
	}
	return int64(result.Checked)
}

// verifyEvidenceSample reads a few stored files back and compares them with
// what the database records. The evidence volume is the one thing this service
// exists to keep, and nothing ever read it back on its own: a disk that lost a
// file, a restore that missed the volume, a blob a power cut left without its
// directory entry -- all of it surfaced when somebody tried to download the
// file, which for evidence is during an audit. The command line tool can check
// everything at once; this checks the least recently checked handful every
// sweep, so a volume comes round on its own.
func (w *Worker) verifyEvidenceSample(ctx context.Context) int64 {
	if w.Vault == nil {
		return 0
	}
	rows, err := w.Store.Pool.Query(ctx, `SELECT e.id,e.original_filename,e.stored_filename,e.key_owner_id,e.key_version,e.current_version,e.size_bytes,e.sha256,COALESCE(r.review_number,'')
                FROM evidences e
                LEFT JOIN submission_items si ON si.id=e.submission_item_id
                LEFT JOIN submissions sub ON sub.id=si.submission_id
                LEFT JOIN review_requests r ON r.id=sub.review_request_id
                WHERE e.deleted_at IS NULL AND e.purged_at IS NULL
                ORDER BY e.verified_at NULLS FIRST, e.created_at LIMIT $1`, evidenceSamplePerSweep)
	if err != nil {
		w.Store.Log(ctx, "ERROR", "", "maintenance", "evidence verification query failed", map[string]any{"error": err.Error()})
		return 0
	}
	type blob struct {
		id, filename, stored, owner, digest, review string
		keyVersion, version                         int
		size                                        int64
	}
	var sample []blob
	for rows.Next() {
		var b blob
		if rows.Scan(&b.id, &b.filename, &b.stored, &b.owner, &b.keyVersion, &b.version, &b.size, &b.digest, &b.review) == nil {
			sample = append(sample, b)
		}
	}
	rows.Close()

	var checked int64
	var broken []string
	for _, b := range sample {
		reason := w.Vault.VerifyBlob(ctx, b.id, b.stored, b.owner, b.keyVersion, b.version, b.size, b.digest)
		// The timestamp moves either way: a file that cannot be read must not
		// be re-checked every sweep in place of files nobody has looked at yet,
		// and the administrators have already been told about it.
		_, _ = w.Store.Pool.Exec(ctx, `UPDATE evidences SET verified_at=now(),verify_error=$2 WHERE id=$1`, b.id, reason)
		checked++
		if reason == "" {
			continue
		}
		w.Store.Log(ctx, "ERROR", "", "maintenance", "stored evidence does not match its record", map[string]any{"evidence_id": b.id, "filename": b.filename, "review": b.review, "reason": reason})
		label := b.filename
		if b.review != "" {
			label = fmt.Sprintf("%s(%s)", b.filename, b.review)
		}
		broken = append(broken, label+": "+reason)
	}
	if len(broken) > 0 {
		w.alertUnreadableEvidence(ctx, broken)
	}
	return checked
}

// alertUnreadableEvidence tells the administrators, once per reminder window,
// that the volume no longer holds what the database says it holds.
func (w *Worker) alertUnreadableEvidence(ctx context.Context, broken []string) {
	admins, err := w.uninformedAdmins(ctx, "EVIDENCE_UNREADABLE")
	if err != nil || len(admins) == 0 {
		return
	}
	named := broken
	if len(named) > 3 {
		named = named[:3]
	}
	body := fmt.Sprintf("증적 %d건을 저장소에서 읽을 수 없거나 기록과 다릅니다: %s", len(broken), strings.Join(named, " / "))
	if len(broken) > len(named) {
		body += fmt.Sprintf(" 외 %d건", len(broken)-len(named))
	}
	body += ". 백업본 복구가 필요할 수 있습니다. `seccheck verify-evidence`로 전체를 점검하세요."
	for _, admin := range admins {
		_ = w.Store.Notify(ctx, admin, "EVIDENCE_UNREADABLE", "증적 무결성 확인 실패", body, "", "")
	}
}

// requeueAbandonedJobs returns work whose worker went away to the queue. Both
// workers reset stale RUNNING rows when they start, but only then and only for
// locks older than the same window -- a restart in the middle of a job leaves a
// lock a few seconds old, which that sweep skips and nothing ever looks at
// again. The job then stays RUNNING for ever: for an evidence scan that means
// the file stays PENDING, the review cannot be submitted, no alarm fires
// (the queue alert counts PENDING work) and the console refuses to retry a
// RUNNING job. This runs every sweep, so the trap closes by itself.
func (w *Worker) requeueAbandonedJobs(ctx context.Context) int64 {
	tag, err := w.Store.Pool.Exec(ctx, `UPDATE jobs SET status='PENDING',locked_at=NULL,available_at=now(),updated_at=now()
                WHERE status='RUNNING' AND locked_at IS NOT NULL AND locked_at<now()-make_interval(mins=>$1)`, int(abandonedAfter.Minutes()))
	if err != nil {
		w.Store.Log(ctx, "ERROR", "", "maintenance", "abandoned job requeue failed", map[string]any{"error": err.Error()})
		return 0
	}
	if n := tag.RowsAffected(); n > 0 {
		w.Store.Log(ctx, "WARN", "", "maintenance", "jobs left running by a stopped worker were requeued", map[string]any{"jobs": n})
		return n
	}
	return 0
}

// remindExpiringAPIKeys warns the owner before a key stops working. The expiry
// was recorded when the key was issued and never mentioned again, so whatever
// was built on it -- a nightly export, an agent over MCP -- failed with 401 one
// morning and the owner had to work out why.
func (w *Worker) remindExpiringAPIKeys(ctx context.Context) int64 {
	rows, err := w.Store.Pool.Query(ctx, `
                UPDATE api_keys SET expiry_reminded_at=now()
                WHERE id IN (
                  SELECT k.id FROM api_keys k JOIN users u ON u.id=k.user_id
                  WHERE k.revoked_at IS NULL AND u.active
                    AND k.expires_at IS NOT NULL
                    AND k.expires_at > now() AND k.expires_at <= now()+make_interval(days=>$1)
                    AND (k.expiry_reminded_at IS NULL OR k.expiry_reminded_at < now()-make_interval(days=>$1))
                  LIMIT 200)
                RETURNING user_id,name,prefix,expires_at`, apiKeyWarningDays)
	if err != nil {
		w.Store.Log(ctx, "ERROR", "", "maintenance", "api key expiry query failed", map[string]any{"error": err.Error()})
		return 0
	}
	type expiring struct {
		owner, name, prefix string
		at                  time.Time
	}
	var pending []expiring
	for rows.Next() {
		var key expiring
		if rows.Scan(&key.owner, &key.name, &key.prefix, &key.at) == nil {
			pending = append(pending, key)
		}
	}
	rows.Close()

	var sent int64
	for _, key := range pending {
		// Rounding down reads as a day early -- a key with 71 hours left is
		// three days away, not two.
		days := int(math.Ceil(time.Until(key.at).Hours() / 24))
		when := fmt.Sprintf("%d일 뒤", days)
		if days < 1 {
			when = "곧"
		}
		body := fmt.Sprintf("API 키 %s(%s…)가 %s 만료됩니다(%s). 만료되면 이 키를 쓰는 연동은 401로 실패합니다. 프로필 > API 키에서 재발급하세요.",
			key.name, key.prefix, when, key.at.In(w.Store.Location(ctx)).Format("2006-01-02 15:04"))
		if err = w.Store.Notify(ctx, key.owner, "API_KEY_EXPIRING", "API 키 만료 임박", body, "", ""); err == nil {
			sent++
		}
	}
	return sent
}

// alertLowStorage warns before the evidence volume fills. An appliance that
// runs offline for years fills its disk eventually, and the first sign used to
// be an upload failing for a person who could do nothing about it -- the
// number was not on any screen and not in any metric.
func (w *Worker) alertLowStorage(ctx context.Context) int64 {
	if w.Vault == nil {
		return 0
	}
	space := w.Vault.Space()
	if space.TotalBytes == 0 {
		return 0
	}
	free := float64(space.FreeBytes) / float64(space.TotalBytes)
	if space.Writable && free > lowStorageRatio && space.FreeBytes > lowStorageBytes {
		return 0
	}
	admins, err := w.uninformedAdmins(ctx, "STORAGE_LOW")
	if err != nil || len(admins) == 0 {
		return 0
	}
	title := "증적 저장 공간이 부족합니다"
	body := fmt.Sprintf("증적 볼륨(%s)의 남은 공간이 %.1fGB (%.0f%%)입니다. 공간이 떨어지면 증적 업로드가 실패합니다.",
		space.Path, float64(space.FreeBytes)/(1<<30), free*100)
	if !space.Writable {
		title = "증적 볼륨에 쓸 수 없습니다"
		body = fmt.Sprintf("증적 볼륨(%s)에 파일을 만들 수 없습니다: %s. 증적 업로드가 모두 실패합니다.", space.Path, space.Detail)
	}
	w.Store.Log(ctx, "ERROR", "", "maintenance", "evidence volume is running out", map[string]any{"free_bytes": space.FreeBytes, "total_bytes": space.TotalBytes, "writable": space.Writable})
	var sent int64
	for _, admin := range admins {
		if err := w.Store.Notify(ctx, admin, "STORAGE_LOW", title, body, "", ""); err == nil {
			sent++
		}
	}
	return sent
}

// alertFailedJobs reports work the queue has given up on. A stalled queue is
// visible as a backlog; a job that has spent all five attempts leaves no
// backlog at all -- the queue reads as empty precisely because the work was
// abandoned. That is what a wrong SMTP password looks like from the outside:
// notifications simply stop, and the page an administrator would check is
// clean. The alert goes to the in-app bell for the same reason the stall
// alert does: the failure it reports is often the one that stops e-mail.
func (w *Worker) alertFailedJobs(ctx context.Context) int64 {
	var failed int64
	var lastError, jobType string
	if err := w.Store.Pool.QueryRow(ctx, `SELECT count(*),COALESCE(max(type),''),COALESCE(max(last_error),'') FROM jobs
                WHERE status='FAILED' AND updated_at>now()-make_interval(hours=>$1)`, int(stallReminder.Hours())).Scan(&failed, &jobType, &lastError); err != nil {
		w.Store.Log(ctx, "ERROR", "", "maintenance", "failed job check failed", map[string]any{"error": err.Error()})
		return 0
	}
	if failed == 0 {
		return 0
	}
	admins, err := w.uninformedAdmins(ctx, "JOB_FAILED")
	if err != nil || len(admins) == 0 {
		return 0
	}
	w.Store.Log(ctx, "ERROR", "", "maintenance", "jobs exhausted their retries", map[string]any{"failed": failed, "type": jobType, "last_error": shorten(lastError, 300)})
	body := fmt.Sprintf("재시도를 모두 소진한 작업이 %d건 있습니다(예: %s). 마지막 오류: %s. 알림 메일이나 증적 검사가 조용히 멈춰 있을 수 있으니 관리자 > 작업 큐에서 확인하세요.", failed, jobType, shorten(lastError, 200))
	var sent int64
	for _, admin := range admins {
		// Deliberately not routed through Store.Notify: an alert about the
		// queue must not depend on the queue, and the mail it would send is
		// exactly what may be failing. The in-app bell carries these two.
		if _, err := w.Store.Pool.Exec(ctx, `INSERT INTO notifications(id,recipient_id,event_type,title,body) VALUES($1,$2,'JOB_FAILED',$3,$4)`,
			store.NewID(), admin, "작업이 재시도를 모두 소진했습니다", body); err == nil {
			sent++
		}
	}
	return sent
}

// uninformedAdmins lists the administrators who have not already been told
// about this kind of trouble inside the reminder window, so an outage that
// lasts a week does not bury the inbox.
func (w *Worker) uninformedAdmins(ctx context.Context, event string) ([]string, error) {
	rows, err := w.Store.Pool.Query(ctx, `SELECT ur.user_id FROM user_roles ur WHERE ur.role_code='SYSTEM_ADMIN'
                AND NOT EXISTS(SELECT 1 FROM notifications n WHERE n.recipient_id=ur.user_id AND n.event_type=$1 AND n.created_at>now()-make_interval(hours=>$2))`, event, int(stallReminder.Hours()))
	if err != nil {
		w.Store.Log(ctx, "ERROR", "", "maintenance", "administrator lookup failed", map[string]any{"event": event, "error": err.Error()})
		return nil, err
	}
	defer rows.Close()
	var admins []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			admins = append(admins, id)
		}
	}
	return admins, rows.Err()
}

// alertStalledQueue puts a stopped queue in front of an administrator. The
// failure it reports is the one that also stops email from being sent, so the
// in-app bell is the only channel that can still carry the warning. The queue
// page shows the same backlog, but nobody watches a page that is usually
// empty.
func (w *Worker) alertStalledQueue(ctx context.Context) int64 {
	var waited float64
	if err := w.Store.Pool.QueryRow(ctx, `SELECT coalesce(extract(epoch FROM now()-min(available_at)),0) FROM jobs WHERE status='PENDING' AND available_at<=now()`).Scan(&waited); err != nil {
		w.Store.Log(ctx, "ERROR", "", "maintenance", "queue backlog check failed", map[string]any{"error": err.Error()})
		return 0
	}
	if waited < stalledAfter.Seconds() {
		return 0
	}
	// Administrators who were already told within the reminder window are
	// skipped, so an outage that lasts a week does not bury the inbox.
	rows, err := w.Store.Pool.Query(ctx, `SELECT ur.user_id FROM user_roles ur WHERE ur.role_code='SYSTEM_ADMIN'
                AND NOT EXISTS(SELECT 1 FROM notifications n WHERE n.recipient_id=ur.user_id AND n.event_type='JOB_QUEUE_STALLED' AND n.created_at>now()-make_interval(hours=>$1))`, int(stallReminder.Hours()))
	if err != nil {
		w.Store.Log(ctx, "ERROR", "", "maintenance", "stalled queue alert query failed", map[string]any{"error": err.Error()})
		return 0
	}
	var admins []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			admins = append(admins, id)
		}
	}
	rows.Close()
	if len(admins) == 0 {
		return 0
	}
	w.Store.Log(ctx, "ERROR", "", "maintenance", "job queue is not draining", map[string]any{"waiting_seconds": int64(waited)})
	body := fmt.Sprintf("실행 시각이 지난 작업이 %d분째 대기 중입니다. 이메일 알림과 증적 악성코드 검사가 멈춘 상태일 수 있으니 서버 로그에서 notify·scanner 구성요소의 오류를 확인하세요.", int64(waited)/60)
	var sent int64
	for _, admin := range admins {
		if _, err := w.Store.Pool.Exec(ctx, `INSERT INTO notifications(id,recipient_id,event_type,title,body) VALUES($1,$2,'JOB_QUEUE_STALLED',$3,$4)`,
			store.NewID(), admin, "작업 큐가 처리되지 않고 있습니다", body); err == nil {
			sent++
		}
	}
	return sent
}

// roleHolder returns the first candidate who is not only still with the
// organisation but still holds the role the reminder is about. An account
// keeps working after the role is taken away, so an "active" reviewer can be
// somebody every review action refuses; chasing them leaves the review looking
// owned while nobody can move it.
func (w *Worker) roleHolder(ctx context.Context, role string, candidates ...string) string {
	for _, id := range candidates {
		if strings.TrimSpace(id) == "" {
			continue
		}
		var ok bool
		if err := w.Store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_roles ur JOIN users u ON u.id=ur.user_id WHERE ur.user_id=$1 AND ur.role_code=$2 AND u.active)`, id, role).Scan(&ok); err != nil {
			continue
		}
		if ok {
			return id
		}
	}
	return ""
}

// activeRecipient returns the first candidate who can still act. A reminder
// addressed to somebody who has left the organisation is worse than none: the
// item looks chased and nobody is chasing it. These dates fall months after
// the review closed, which is exactly when the person who owned it is most
// likely gone.
func (w *Worker) activeRecipient(ctx context.Context, candidates ...string) (string, bool) {
	for i, id := range candidates {
		if strings.TrimSpace(id) == "" {
			continue
		}
		var active bool
		if err := w.Store.Pool.QueryRow(ctx, `SELECT active FROM users WHERE id=$1`, id).Scan(&active); err != nil {
			continue
		}
		if active {
			return id, i > 0
		}
	}
	return "", false
}

// remindDueFollowUps tells the service owner when an action promised at
// review time is nearly due or already late. The register shows the same
// thing, but nobody opens a report in the months between reviews -- which is
// precisely the window these actions live in.
//
// The requester is the recipient: the action is a condition on their service
// and the remediation is theirs. The security team watches the register.
func (w *Worker) remindDueFollowUps(ctx context.Context) int64 {
	rows, err := w.Store.Pool.Query(ctx, `
                UPDATE review_results SET follow_up_reminded_at=now()
                WHERE id IN (
                  SELECT rr.id FROM review_results rr
                  JOIN submission_items si ON si.id=rr.submission_item_id
                  JOIN submissions sub ON sub.id=si.submission_id
                  JOIN review_requests r ON r.id=sub.review_request_id
                  WHERE btrim(rr.follow_up)<>'' AND rr.follow_up_done_at IS NULL AND r.status<>'CANCELLED'
                    AND rr.follow_up_due_date IS NOT NULL
                    AND rr.follow_up_due_date <= display_today()+7
                    AND (rr.follow_up_reminded_at IS NULL OR rr.follow_up_reminded_at < now()-interval '7 days')
                  LIMIT 200)
                RETURNING id,submission_item_id,follow_up,follow_up_due_date`)
	if err != nil {
		w.Store.Log(ctx, "ERROR", "", "maintenance", "follow-up reminder query failed", map[string]any{"error": err.Error()})
		return 0
	}
	type reminder struct {
		id, itemID, action string
		due                time.Time
	}
	var pending []reminder
	for rows.Next() {
		var item reminder
		if err = rows.Scan(&item.id, &item.itemID, &item.action, &item.due); err != nil {
			continue
		}
		pending = append(pending, item)
	}
	rows.Close()

	var sent int64
	for _, item := range pending {
		var reviewID, number, service, requester, code string
		var reviewer *string
		if err = w.Store.Pool.QueryRow(ctx, `SELECT r.id,r.review_number,r.service_name,r.requester_id,r.reviewer_id,si.item_code
                        FROM submission_items si
                        JOIN submissions sub ON sub.id=si.submission_id
                        JOIN review_requests r ON r.id=sub.review_request_id
                        WHERE si.id=$1`, item.itemID).Scan(&reviewID, &number, &service, &requester, &reviewer, &code); err != nil {
			continue
		}
		title := "후속조치 기한 임박"
		if w.pastDue(ctx, item.due) {
			title = "후속조치 기한 초과"
		}
		body := fmt.Sprintf("%s(%s) %s 항목의 후속조치 기한이 %s입니다: %s", number, service, code, item.due.Format("2006-01-02"), shorten(item.action, 200))
		// The requester owns the remediation, but if they have left the
		// reviewer is told instead, and told why -- somebody has to know the
		// action has no owner.
		fallback := ""
		if reviewer != nil {
			fallback = *reviewer
		}
		recipient, reassigned := w.activeRecipient(ctx, requester, fallback)
		if recipient == "" {
			w.Store.Log(ctx, "WARN", "", "maintenance", "후속조치 기한이 되었으나 알릴 활성 사용자가 없습니다.", map[string]any{"review_number": number, "item_code": code})
			continue
		}
		if reassigned {
			body += " (원 담당자 계정이 비활성 상태여서 검토자에게 전달합니다. 담당자를 다시 지정하세요.)"
		}
		if err = w.Store.Notify(ctx, recipient, "FOLLOW_UP_DUE", title, body, "REVIEW_REQUEST", reviewID); err == nil {
			sent++
		}
	}
	return sent
}

// pastDue answers whether a date has gone by where the installation lives.
// Comparing against the container's UTC clock made the wording wrong for part
// of every day in a zone ahead of UTC -- a deadline that ran out at midnight
// was still described as "임박" until nine in the morning.
func (w *Worker) pastDue(ctx context.Context, day time.Time) bool {
	var passed bool
	if err := w.Store.Pool.QueryRow(ctx, `SELECT $1::date < display_today()`, day).Scan(&passed); err != nil {
		return false
	}
	return passed
}

// remindApproachingOpenDates warns while there is still time to act. The
// planned open date is the date the service goes live whether or not the
// review is finished; it was recorded and displayed and nothing ever chased
// it, so a review could still be in progress on the morning of the launch.
func (w *Worker) remindApproachingOpenDates(ctx context.Context) int64 {
	rows, err := w.Store.Pool.Query(ctx, `
                UPDATE review_requests SET open_date_reminded_at=now()
                WHERE id IN (
                  SELECT r.id FROM review_requests r
                  WHERE r.status NOT IN ('APPROVED','CLOSED','CANCELLED','REJECTED')
                    AND r.planned_open_date IS NOT NULL
                    AND r.planned_open_date <= display_today()+$1::int
                    AND (r.open_date_reminded_at IS NULL OR r.open_date_reminded_at < now()-make_interval(days=>$1))
                  LIMIT 200)
                RETURNING id,review_number,service_name,status,requester_id,COALESCE(reviewer_id,''),COALESCE(approver_id,''),planned_open_date`, openDateWarningDays)
	if err != nil {
		w.Store.Log(ctx, "ERROR", "", "maintenance", "open date reminder query failed", map[string]any{"error": err.Error()})
		return 0
	}
	type launching struct {
		id, number, service, status, requester, reviewer, approver string
		openOn                                                     time.Time
	}
	var pending []launching
	for rows.Next() {
		var item launching
		if rows.Scan(&item.id, &item.number, &item.service, &item.status, &item.requester, &item.reviewer, &item.approver, &item.openOn) == nil {
			pending = append(pending, item)
		}
	}
	rows.Close()

	var sent int64
	for _, item := range pending {
		title := "오픈 예정일이 다가왔습니다"
		when := fmt.Sprintf("오픈 예정일이 %s입니다", item.openOn.Format("2006-01-02"))
		if w.pastDue(ctx, item.openOn) {
			title = "오픈 예정일이 지났습니다"
			when = fmt.Sprintf("오픈 예정일 %s이 지났습니다", item.openOn.Format("2006-01-02"))
		}
		body := fmt.Sprintf("%s(%s)의 %s. 심의는 아직 %s 상태입니다.", item.number, item.service, when, statusInKorean(item.status))
		// Both sides need this: whoever holds the review has to finish it, and
		// the requester is the one who has to decide whether the launch moves.
		holder := ""
		if item.status == "APPROVAL_PENDING" {
			holder = w.roleHolder(ctx, "APPROVER", item.approver)
		}
		if holder == "" {
			holder = w.roleHolder(ctx, "SECURITY_REVIEWER", item.reviewer)
		}
		requester, _ := w.activeRecipient(ctx, item.requester)
		for _, recipient := range dedupe(requester, holder) {
			if err = w.Store.Notify(ctx, recipient, "OPEN_DATE_NEAR", title, body, "REVIEW_REQUEST", item.id); err == nil {
				sent++
			}
		}
	}
	return sent
}

// statusInKorean names a state the way the screens do, so a message about a
// review reads the same as the review itself.
func statusInKorean(status string) string {
	switch status {
	case "DRAFT":
		return "작성 중"
	case "SUBMITTED":
		return "제출 완료"
	case "RESUBMITTED":
		return "재제출"
	case "REVIEWING":
		return "검토 중"
	case "CHANGE_REQUESTED":
		return "보완 요청"
	case "APPROVAL_PENDING":
		return "승인 대기"
	}
	return status
}

func dedupe(ids ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

type stalled struct {
	id, number, service, status, reviewer, approver string
	since                                           time.Time
}

// remindStalledReviews tells whoever the review is waiting on. Reminders were
// only ever aimed at the requester side -- change request due, follow-up due --
// so a review submitted and never picked up, started and left, or sitting for a
// signature simply aged, with the requester able to see no movement and unable
// to do anything about it.
func (w *Worker) remindStalledReviews(ctx context.Context) int64 {
	rows, err := w.Store.Pool.Query(ctx, `
                UPDATE review_requests SET stalled_reminded_at=now()
                WHERE id IN (
                  SELECT r.id FROM review_requests r
                  WHERE r.status = ANY($2)
                    AND r.updated_at < now()-make_interval(days=>$1)
                    AND (r.stalled_reminded_at IS NULL OR r.stalled_reminded_at < now()-make_interval(days=>$1))
                  LIMIT 200)
                RETURNING id,review_number,service_name,status,COALESCE(reviewer_id,''),COALESCE(approver_id,''),updated_at`, stalledReviewDays, StalledStatuses)
	if err != nil {
		w.Store.Log(ctx, "ERROR", "", "maintenance", "stalled review query failed", map[string]any{"error": err.Error()})
		return 0
	}
	var pending []stalled
	for rows.Next() {
		var item stalled
		if rows.Scan(&item.id, &item.number, &item.service, &item.status, &item.reviewer, &item.approver, &item.since) == nil {
			pending = append(pending, item)
		}
	}
	rows.Close()

	var sent int64
	var unclaimed []stalled
	for _, item := range pending {
		days := int(time.Since(item.since).Hours() / 24)
		waiting := map[string]string{
			"SUBMITTED":        "검토 시작을 기다리고 있습니다",
			"RESUBMITTED":      "재검토를 기다리고 있습니다",
			"REVIEWING":        "검토가 진행 중인 상태로 멈춰 있습니다",
			"APPROVAL_PENDING": "최종 승인을 기다리고 있습니다",
		}[item.status]
		body := fmt.Sprintf("%s(%s)가 %d일째 %s. 담당하신 건을 확인해 주세요.", item.number, item.service, days, waiting)
		// Whoever the state says owns it gets their own reminder, because it
		// is their review. A review nobody has taken belongs to the reviewers
		// as a group and is gathered below: one reminder each per sweep, not
		// one per reviewer per review, which for a neglected queue would be a
		// flood that teaches people to ignore the alert.
		recipient := ""
		if item.status == "APPROVAL_PENDING" {
			recipient = w.roleHolder(ctx, "APPROVER", item.approver)
			if recipient == "" {
				recipient = w.roleHolder(ctx, "SECURITY_REVIEWER", item.reviewer)
			}
		} else {
			recipient = w.roleHolder(ctx, "SECURITY_REVIEWER", item.reviewer)
		}
		if recipient == "" {
			// Nobody who can act owns it, so it belongs to the group -- the
			// same place a review with no reviewer at all goes.
			unclaimed = append(unclaimed, item)
			continue
		}
		if err = w.Store.Notify(ctx, recipient, "REVIEW_STALLED", "심의가 멈춰 있습니다", body, "REVIEW_REQUEST", item.id); err == nil {
			sent++
		}
	}
	return sent + w.remindUnclaimedReviews(ctx, unclaimed)
}

// remindUnclaimedReviews tells the reviewers, once, about everything waiting
// with no owner. It names the oldest few and counts the rest so the message
// stays readable when the queue has been left for a while.
func (w *Worker) remindUnclaimedReviews(ctx context.Context, waiting []stalled) int64 {
	if len(waiting) == 0 {
		return 0
	}
	reviewers := w.securityReviewers(ctx)
	if len(reviewers) == 0 {
		w.Store.Log(ctx, "WARN", "", "maintenance", "담당자 없는 심의가 밀려 있으나 알릴 활성 보안 담당자가 없습니다.", map[string]any{"reviews": len(waiting)})
		return 0
	}
	oldest := waiting[0]
	var named []string
	for i, item := range waiting {
		if item.since.Before(oldest.since) {
			oldest = item
		}
		if i < 3 {
			named = append(named, fmt.Sprintf("%s(%s)", item.number, item.service))
		}
	}
	body := fmt.Sprintf("담당자가 지정되지 않은 심의 %d건이 3일 이상 대기 중입니다: %s", len(waiting), strings.Join(named, ", "))
	if len(waiting) > len(named) {
		body += fmt.Sprintf(" 외 %d건", len(waiting)-len(named))
	}
	body += fmt.Sprintf(". 가장 오래된 건은 %d일째입니다. 보안 검토 Queue에서 담당자를 지정하세요.", int(time.Since(oldest.since).Hours()/24))
	var sent int64
	for _, reviewer := range reviewers {
		if err := w.Store.Notify(ctx, reviewer, "REVIEW_STALLED", "담당자 없는 심의가 대기 중입니다", body, "REVIEW_REQUEST", oldest.id); err == nil {
			sent++
		}
	}
	return sent
}

// securityReviewers lists the active accounts that own the review queue, for
// the reviews nobody has taken yet.
func (w *Worker) securityReviewers(ctx context.Context) []string {
	rows, err := w.Store.Pool.Query(ctx, `SELECT ur.user_id FROM user_roles ur JOIN users u ON u.id=ur.user_id
                WHERE ur.role_code='SECURITY_REVIEWER' AND u.active LIMIT 20`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var reviewers []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			reviewers = append(reviewers, id)
		}
	}
	return reviewers
}

// purgeDeletedEvidence reclaims the encrypted blobs behind evidence that was
// deleted longer ago than the configured window. The metadata row stays, so
// the audit trail still shows the file existed, its hash and who removed it;
// only the ciphertext goes.
func (w *Worker) purgeDeletedEvidence(ctx context.Context) int64 {
	if w.Vault == nil {
		return 0
	}
	var cfg struct {
		Days int `json:"deleted_evidence_retention_days"`
	}
	if _, err := w.Store.Setting(ctx, "upload", &cfg); err != nil {
		return 0
	}
	if cfg.Days < 1 || cfg.Days > 36500 {
		cfg.Days = 90
	}
	rows, err := w.Store.Pool.Query(ctx, `SELECT ev.id,ev.evidence_id,ev.stored_filename,ev.version,e.original_filename,e.sha256,COALESCE(sub.review_request_id,'')
                FROM evidence_versions ev
                JOIN evidences e ON e.id=ev.evidence_id
                LEFT JOIN submission_items si ON si.id=e.submission_item_id
                LEFT JOIN submissions sub ON sub.id=si.submission_id
                WHERE e.deleted_at IS NOT NULL AND e.deleted_at < now()-make_interval(days=>$1)
                  AND ev.purged_at IS NULL
                ORDER BY e.deleted_at LIMIT 2000`, cfg.Days)
	if err != nil {
		w.Store.Log(ctx, "ERROR", "", "maintenance", "evidence purge query failed", map[string]any{"error": err.Error()})
		return 0
	}
	type blob struct {
		versionID, evidenceID, stored, filename, digest, reviewID string
		version                                                   int
	}
	var blobs []blob
	for rows.Next() {
		var b blob
		if rows.Scan(&b.versionID, &b.evidenceID, &b.stored, &b.version, &b.filename, &b.digest, &b.reviewID) == nil {
			blobs = append(blobs, b)
		}
	}
	rows.Close()

	var purged int64
	touched := map[string]bool{}
	for _, b := range blobs {
		// A file that is already gone still counts as purged: the point is that
		// the ciphertext is not on the volume any more.
		if err := os.Remove(w.Vault.Path(b.stored)); err != nil && !os.IsNotExist(err) {
			w.Store.Log(ctx, "ERROR", "", "maintenance", "evidence blob could not be removed", map[string]any{"evidence_id": b.evidenceID, "error": err.Error()})
			continue
		}
		if _, err := w.Store.Pool.Exec(ctx, `UPDATE evidence_versions SET purged_at=now() WHERE id=$1`, b.versionID); err != nil {
			continue
		}
		// Destroying the only copy of a piece of evidence belongs in the
		// tamper-evident record, not only in the application log -- which the
		// same retention sweep deletes, so the account of the destruction
		// would expire along with it.
		_ = w.Store.Audit(ctx, store.AuditEvent{UserName: "system", EventType: "PURGE_EVIDENCE", TargetType: "EVIDENCE", TargetID: b.evidenceID,
			After: map[string]any{"filename": b.filename, "version": b.version, "sha256": b.digest, "review_request_id": b.reviewID, "retention_days": cfg.Days}})
		purged++
		touched[b.evidenceID] = true
	}
	for evidenceID := range touched {
		_, _ = w.Store.Pool.Exec(ctx, `UPDATE evidences SET purged_at=now() WHERE id=$1 AND purged_at IS NULL
                        AND NOT EXISTS(SELECT 1 FROM evidence_versions v WHERE v.evidence_id=$1 AND v.purged_at IS NULL)`, evidenceID)
	}
	if purged > 0 {
		w.Store.Log(ctx, "INFO", "", "maintenance", "deleted evidence purged from the volume", map[string]any{"files": purged, "retention_days": cfg.Days})
	}
	return purged
}

// remindDueChangeRequests notifies the assignee once when a change request is
// close to its due date or already late. The due date was captured from the
// start but nothing ever acted on it.
// countOrphanBlobs answers "why is the disk filling up". The definition of an
// orphan lives with the vault, which owns the directory, so the hourly report
// and `seccheck verify-evidence` cannot disagree about what one is. The sweep
// asks for a bounded walk and skips anything written in the last day, which
// may be an upload still in flight.
func (w *Worker) countOrphanBlobs(ctx context.Context) int64 {
	if w.Vault == nil {
		return 0
	}
	paths, bytes, scanned := w.Vault.OrphanBlobs(ctx, 24*time.Hour, orphanScanLimit)
	if len(paths) > 0 {
		w.Store.Log(ctx, "WARN", "", "maintenance", "데이터베이스에 기록이 없는 증적 파일이 있습니다. 저장 공간을 차지하지만 어떤 심의에서도 열리지 않습니다.",
			map[string]any{"orphan_files": len(paths), "orphan_bytes": bytes, "scanned_files": scanned})
	}
	return int64(len(paths))
}

// A cancelled review is a service that is not being built, so the reminders
// hanging off it are addressed to nobody: the correction cannot be carried out
// and the review cannot be reopened. They kept going out every three days
// anyway, to the requester who had just cancelled it.
func (w *Worker) remindDueChangeRequests(ctx context.Context) int64 {
	rows, err := w.Store.Pool.Query(ctx, `
                UPDATE change_requests SET reminded_at=now()
                WHERE id IN (
                  SELECT c.id FROM change_requests c
                  JOIN review_requests r ON r.id=c.review_request_id
                  WHERE c.status<>'VERIFIED' AND r.status<>'CANCELLED' AND c.due_date IS NOT NULL
                    AND c.due_date <= display_today()+2
                    AND (c.reminded_at IS NULL OR c.reminded_at < now()-interval '3 days')
                  LIMIT 200)
                RETURNING id,review_request_id,COALESCE(assignee_id,requester_id),due_date`)
	if err != nil {
		w.Store.Log(ctx, "ERROR", "", "maintenance", "due-date reminder query failed", map[string]any{"error": err.Error()})
		return 0
	}
	type reminder struct {
		id, reviewID, recipient string
		due                     time.Time
	}
	var pending []reminder
	for rows.Next() {
		var item reminder
		if err = rows.Scan(&item.id, &item.reviewID, &item.recipient, &item.due); err != nil {
			continue
		}
		pending = append(pending, item)
	}
	rows.Close()

	var sent int64
	for _, item := range pending {
		var number, service string
		if err = w.Store.Pool.QueryRow(ctx, `SELECT review_number,service_name FROM review_requests WHERE id=$1`, item.reviewID).Scan(&number, &service); err != nil {
			continue
		}
		title := "보완 조치 기한 임박"
		body := fmt.Sprintf("%s(%s)의 보완 요청 기한이 %s입니다. 조치 후 재제출하세요.", number, service, item.due.Format("2006-01-02"))
		if w.pastDue(ctx, item.due) {
			title = "보완 조치 기한 초과"
			body = fmt.Sprintf("%s(%s)의 보완 요청이 %s 기한을 넘겼습니다.", number, service, item.due.Format("2006-01-02"))
		}
		// An open change request blocks resubmission, so a reminder that lands
		// on a departed assignee leaves the review stuck with nobody told.
		var owner, reviewer string
		_ = w.Store.Pool.QueryRow(ctx, `SELECT requester_id,COALESCE(reviewer_id,'') FROM review_requests WHERE id=$1`, item.reviewID).Scan(&owner, &reviewer)
		recipient, reassigned := w.activeRecipient(ctx, item.recipient, owner, reviewer)
		if recipient == "" {
			w.Store.Log(ctx, "WARN", "", "maintenance", "보완 요청 기한이 되었으나 알릴 활성 사용자가 없습니다.", map[string]any{"review_number": number})
			continue
		}
		if reassigned {
			body += " (원 담당자 계정이 비활성 상태입니다. 담당자를 다시 지정하세요.)"
		}
		if err = w.Store.Notify(ctx, recipient, "CHANGE_REQUEST_DUE", title, body, "REVIEW_REQUEST", item.reviewID); err == nil {
			sent++
		}
	}
	return sent
}

func (w *Worker) retentionDays(ctx context.Context) int {
	var general struct {
		RetentionDays int `json:"retention_days"`
	}
	if _, err := w.Store.Setting(ctx, "general", &general); err != nil {
		return 1825
	}
	if general.RetentionDays < 30 || general.RetentionDays > 36500 {
		return 1825
	}
	return general.RetentionDays
}

func (w *Worker) delete(ctx context.Context, query string, args ...any) int64 {
	var total int64
	for i := 0; i < maxBatches; i++ {
		if ctx.Err() != nil {
			return total
		}
		tag, err := w.Store.Pool.Exec(ctx, query, append([]any{batchSize}, args...)...)
		if err != nil {
			w.Store.Log(ctx, "ERROR", "", "maintenance", "retention sweep failed", map[string]any{"error": err.Error()})
			return total
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < batchSize {
			return total
		}
	}
	return total
}

// shorten keeps a notification readable when the action written on a verdict
// runs long.
func shorten(v string, n int) string {
	runes := []rune(v)
	if len(runes) <= n {
		return v
	}
	return string(runes[:n]) + "…"
}
