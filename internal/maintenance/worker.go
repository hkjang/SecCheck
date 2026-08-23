// Package maintenance keeps the operational tables bounded. SecCheck runs
// offline for years at a time, so expired authentication state, finished jobs
// and application logs have to be reclaimed by the service itself rather than
// by an external cron job.
package maintenance

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/vault"
)

// Deletes run in bounded batches so a first sweep over a long-neglected
// installation never holds a single long transaction.
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
	stalledReviewDays = 3
	// How close a planned open date has to be before the people who can still
	// finish the review are told, and how long before they are told again.
	openDateWarningDays = 3
	// Room below either of these is worth waking somebody for: proportionally
	// nearly full, or absolutely close enough that a few uploads finish it.
	lowStorageRatio = 0.10
	lowStorageBytes = 2 << 30
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
	removed["purged_evidence_files"] = w.purgeDeletedEvidence(ctx)
	total := int64(0)
	for _, n := range removed {
		total += n
	}
	if total > 0 {
		w.Store.Log(ctx, "INFO", "", "maintenance", "retention sweep completed", map[string]any{"retention_days": retention, "removed": removed})
	}
	return removed
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
                  WHERE btrim(rr.follow_up)<>'' AND rr.follow_up_done_at IS NULL
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
			holder, _ = w.activeRecipient(ctx, item.approver, item.reviewer)
		} else {
			holder, _ = w.activeRecipient(ctx, item.reviewer)
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
                  WHERE r.status IN ('SUBMITTED','RESUBMITTED','REVIEWING','APPROVAL_PENDING')
                    AND r.updated_at < now()-make_interval(days=>$1)
                    AND (r.stalled_reminded_at IS NULL OR r.stalled_reminded_at < now()-make_interval(days=>$1))
                  LIMIT 200)
                RETURNING id,review_number,service_name,status,COALESCE(reviewer_id,''),COALESCE(approver_id,''),updated_at`, stalledReviewDays)
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
			recipient, _ = w.activeRecipient(ctx, item.approver, item.reviewer)
		} else {
			recipient, _ = w.activeRecipient(ctx, item.reviewer)
		}
		if recipient == "" {
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
func (w *Worker) remindDueChangeRequests(ctx context.Context) int64 {
	rows, err := w.Store.Pool.Query(ctx, `
                UPDATE change_requests SET reminded_at=now()
                WHERE id IN (
                  SELECT c.id FROM change_requests c
                  WHERE c.status<>'VERIFIED' AND c.due_date IS NOT NULL
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
