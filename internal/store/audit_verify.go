package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// The hash chain is what makes the audit log tamper-evident, and evidence that
// is only looked at when somebody remembers to press a button is not evidence
// of much. Verification lives here so that the console and the maintenance
// worker prove the chain the same way.

// ChainCheck is the result of walking the chain from a known-good anchor.
type ChainCheck struct {
	Valid          bool
	Checked        int
	FromSequence   int64
	HeadSequence   int64
	HeadHash       string
	FailedEventID  string
	FailedSequence int64
	Reason         string
}

// AuditCheckpoint reports how far the chain has already been proved. An empty
// hash means nothing has been proved yet, so a run has no anchor and has to
// start from the beginning.
func (s *Store) AuditCheckpoint(ctx context.Context) (int64, string, error) {
	var sequence int64
	var hash string
	if err := s.Pool.QueryRow(ctx, `SELECT verified_sequence,verified_hash FROM audit_chain_state WHERE id=1`).Scan(&sequence, &hash); err != nil {
		return 0, "", err
	}
	if hash == "" {
		return 0, "", nil
	}
	return sequence, hash, nil
}

// VerifyAuditChain re-hashes every event after fromSequence and checks that
// each one links to the one before it, ending at the recorded head.
func (s *Store) VerifyAuditChain(ctx context.Context, fromSequence int64, previous string) (ChainCheck, error) {
	out := ChainCheck{FromSequence: fromSequence}
	rows, err := s.Pool.Query(ctx, `SELECT event_id,previous_hash,canonical_payload,event_hash,chain_sequence FROM audit_logs WHERE chain_sequence>$1 ORDER BY chain_sequence`, fromSequence)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	expected := fromSequence + 1
	for rows.Next() {
		var id, linked, payload, storedHash string
		var sequence int64
		if err = rows.Scan(&id, &linked, &payload, &storedHash, &sequence); err != nil {
			return out, err
		}
		out.Checked++
		if payload == "" || linked != previous || sequence != expected {
			out.FailedEventID, out.FailedSequence, out.Reason = id, sequence, "chain link or canonical payload mismatch"
			return out, nil
		}
		hash := sha256.Sum256([]byte(payload))
		if hex.EncodeToString(hash[:]) != storedHash {
			out.FailedEventID, out.FailedSequence, out.Reason = id, sequence, "event hash mismatch"
			return out, nil
		}
		previous = storedHash
		expected++
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	var head string
	var sequence int64
	if err = s.Pool.QueryRow(ctx, `SELECT head_hash,sequence FROM audit_chain_state WHERE id=1`).Scan(&head, &sequence); err != nil || head != previous || sequence != expected-1 {
		out.FailedSequence, out.Reason = sequence, "chain head state mismatch"
		return out, nil
	}
	out.Valid, out.HeadHash, out.HeadSequence = true, head, sequence
	return out, nil
}

// MarkAuditChainVerified moves the anchor forward so the next routine check
// only has to read what was appended since.
func (s *Store) MarkAuditChainVerified(ctx context.Context, sequence int64, hash string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE audit_chain_state SET verified_sequence=$1,verified_hash=$2,verified_at=now() WHERE id=1`, sequence, hash)
	return err
}
