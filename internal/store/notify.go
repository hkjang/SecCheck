package store

import (
	"context"
	"errors"

	"github.com/hkjang/SecCheck/internal/mail"
	"github.com/jackc/pgx/v5"
)

type actorKey struct{}

// WithActor marks the context with the person whose action is being
// recorded, so that a notification their own action produces for themselves
// is kept on the bell and never mailed: nobody wants a message about what
// they just did.
func WithActor(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, actorKey{}, userID)
}

// ActorID returns what WithActor recorded, or "" for a background worker.
func ActorID(ctx context.Context) string {
	id, _ := ctx.Value(actorKey{}).(string)
	return id
}

// Notify records a notification and, when the recipient wants mail as it
// happens, queues the e-mail in the same transaction.
//
// The background workers used to insert the row directly and stop there, so a
// deadline reminder reached a recipient on immediate delivery only if they
// happened to open the service -- the digest picked it up for daily readers,
// and nobody picked it up for everyone else. A reminder exists precisely to
// reach somebody who is not looking at the screen, so both paths go through
// here now.
func (s *Store) Notify(ctx context.Context, recipient, event, title, body, targetType, targetID string) error {
	if recipient == "" {
		return errors.New("no recipient")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = s.NotifyTx(ctx, tx, recipient, event, title, body, targetType, targetID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// NotifyTx is Notify for a caller that already holds a transaction, so the
// notification lives or dies with the change that caused it.
func (s *Store) NotifyTx(ctx context.Context, tx pgx.Tx, recipient, event, title, body, targetType, targetID string) error {
	return s.notifyTx(ctx, tx, recipient, event, title, body, targetType, targetID, "")
}

// NotifyItem is Notify for a message about one checklist item. The item
// travels with the notice so the reader lands on it instead of on the review
// that holds a few hundred of them.
func (s *Store) NotifyItem(ctx context.Context, recipient, event, title, body, reviewID, itemID string) error {
	if recipient == "" {
		return errors.New("no recipient")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = s.notifyTx(ctx, tx, recipient, event, title, body, "REVIEW_REQUEST", reviewID, itemID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) notifyTx(ctx context.Context, tx pgx.Tx, recipient, event, title, body, targetType, targetID, itemID string) error {
	if recipient == "" {
		return errors.New("no recipient")
	}
	id := NewID()
	if _, err := tx.Exec(ctx, `INSERT INTO notifications(id,recipient_id,event_type,title,body,target_type,target_id,item_id) VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''))`,
		id, recipient, event, title, body, targetType, targetID, itemID); err != nil {
		return err
	}
	if recipient == ActorID(ctx) && !mail.AboutTheService(event) {
		// Their own doing: on the bell, out of the mail and the digest.
		_, err := tx.Exec(ctx, `UPDATE notifications SET emailed_at=now() WHERE id=$1`, id)
		return err
	}
	if !s.WantsImmediateMail(ctx, tx, recipient, event) {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO jobs(id,type,payload) VALUES($1,'SEND_EMAIL',jsonb_build_object('notification_id',$2::text))`, NewID(), id); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE notifications SET emailed_at=now() WHERE id=$1`, id)
	return err
}

// WantsImmediateMail answers whether this event should be mailed now. A
// daily-digest reader is left alone: emailed_at stays null and the digest
// worker collects it, minus whatever they have muted. An event type the
// administrator has switched off, or one no switch covers, is never mailed.
func (s *Store) WantsImmediateMail(ctx context.Context, tx pgx.Tx, recipient, event string) bool {
	cfg, err := mail.Load(ctx, s, nil)
	if err != nil || !cfg.Enabled || !cfg.Allows(event) {
		return false
	}
	var enabled bool
	var digest string
	var muted []string
	err = tx.QueryRow(ctx, `SELECT email_enabled,digest,muted_events FROM notification_preferences WHERE user_id=$1`, recipient).Scan(&enabled, &digest, &muted)
	if errors.Is(err, pgx.ErrNoRows) {
		// No preference recorded means the default: everything, immediately.
		return true
	}
	if err != nil || !enabled {
		return false
	}
	for _, code := range muted {
		if code == event {
			return false
		}
	}
	return digest != "DAILY"
}
