// Package maintenance keeps the operational tables bounded. SecCheck runs
// offline for years at a time, so expired authentication state, finished jobs
// and application logs have to be reclaimed by the service itself rather than
// by an external cron job.
package maintenance

import (
	"context"
	"fmt"
	"time"

	"github.com/hkjang/SecCheck/internal/store"
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
)

type Worker struct{ Store *store.Store }

func New(s *store.Store) *Worker { return &Worker{Store: s} }

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
	total := int64(0)
	for _, n := range removed {
		total += n
	}
	if total > 0 {
		w.Store.Log(ctx, "INFO", "", "maintenance", "retention sweep completed", map[string]any{"retention_days": retention, "removed": removed})
	}
	return removed
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
                    AND c.due_date <= current_date+2
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
		if item.due.Before(time.Now().Truncate(24 * time.Hour)) {
			title = "보완 조치 기한 초과"
			body = fmt.Sprintf("%s(%s)의 보완 요청이 %s 기한을 넘겼습니다.", number, service, item.due.Format("2006-01-02"))
		}
		if _, err = w.Store.Pool.Exec(ctx, `INSERT INTO notifications(id,recipient_id,event_type,title,body) VALUES($1,$2,'CHANGE_REQUEST_DUE',$3,$4)`, store.NewID(), item.recipient, title, body); err == nil {
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
