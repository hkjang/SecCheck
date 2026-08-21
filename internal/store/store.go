package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct{ Pool *pgxpool.Pool }

type User struct {
	ID, Username, DisplayName, Email, Department, PasswordHash, AuthSource string
	Active                                                                 bool
	Roles                                                                  []string
}

type AuditEvent struct {
	UserID, UserName, SourceIP, SessionID, EventType, TargetType, TargetID, RequestID, Result string
	Before, After                                                                             any
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{Pool: pool}, nil
}

func (s *Store) Close() { s.Pool.Close() }

// Migrate applies every embedded migration that this database has not seen
// yet, in file-name order and one transaction each. Installations created
// before numbered migrations existed already recorded version 1, so the
// baseline is skipped for them and only the newer files run.
func (s *Store) Migrate(ctx context.Context) error {
	files, err := MigrationFiles()
	if err != nil {
		return err
	}
	if _, err = s.Pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	applied, err := s.appliedMigrations(ctx)
	if err != nil {
		return err
	}
	for _, file := range files {
		if applied[file.Version] {
			continue
		}
		body, err := migrations.ReadFile("migrations/" + file.Name)
		if err != nil {
			return err
		}
		if err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(body)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1) ON CONFLICT DO NOTHING`, file.Version)
			return err
		}); err != nil {
			return fmt.Errorf("migration %s: %w", file.Name, err)
		}
	}
	return nil
}

// Migration is one embedded SQL file. Names must start with a zero-padded
// version, for example 002_indexes.sql.
type Migration struct {
	Version int
	Name    string
}

func MigrationFiles() ([]Migration, error) {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	out := make([]Migration, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, found := strings.Cut(name, "_")
		version, convErr := strconv.Atoi(prefix)
		if !found || convErr != nil || version < 1 {
			return nil, fmt.Errorf("migration %q must start with a version number", name)
		}
		out = append(out, Migration{Version: version, Name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i := 1; i < len(out); i++ {
		if out[i].Version == out[i-1].Version {
			return nil, fmt.Errorf("duplicate migration version %d", out[i].Version)
		}
	}
	return out, nil
}

func (s *Store) appliedMigrations(ctx context.Context) (map[int]bool, error) {
	rows, err := s.Pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	applied := map[int]bool{}
	for rows.Next() {
		var version int
		if err = rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}
	return applied, rows.Err()
}

// SchemaVersion reports the highest applied migration, for /api/v1/admin/system
// and for deciding whether an image may be rolled back.
func (s *Store) SchemaVersion(ctx context.Context) int {
	var version int
	_ = s.Pool.QueryRow(ctx, `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&version)
	return version
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	var u User
	err := s.Pool.QueryRow(ctx, `SELECT id,username,display_name,email,department,password_hash,auth_source,active FROM users WHERE lower(username)=lower($1)`, username).
		Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Department, &u.PasswordHash, &u.AuthSource, &u.Active)
	if err != nil {
		return u, err
	}
	u.Roles, err = s.UserRoles(ctx, u.ID)
	return u, err
}

func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	var u User
	err := s.Pool.QueryRow(ctx, `SELECT id,username,display_name,email,department,password_hash,auth_source,active FROM users WHERE id=$1`, id).
		Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Department, &u.PasswordHash, &u.AuthSource, &u.Active)
	if err != nil {
		return u, err
	}
	u.Roles, err = s.UserRoles(ctx, u.ID)
	return u, err
}

func (s *Store) UserRoles(ctx context.Context, id string) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT role_code FROM user_roles WHERE user_id=$1 ORDER BY role_code`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

func (s *Store) UpsertBootstrap(ctx context.Context, id, username, passwordHash string) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash,auth_source) VALUES($1,$2,$2,$3,'local') ON CONFLICT(username) DO UPDATE SET password_hash=CASE WHEN users.password_hash='' THEN EXCLUDED.password_hash ELSE users.password_hash END,active=true,updated_at=now()`, id, username, passwordHash)
		if err != nil {
			return err
		}
		var uid string
		if err = tx.QueryRow(ctx, `SELECT id FROM users WHERE username=$1`, username).Scan(&uid); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO user_roles(user_id,role_code) VALUES($1,'SYSTEM_ADMIN'),($1,'TEMPLATE_ADMIN'),($1,'SECURITY_REVIEWER'),($1,'REQUESTER'),($1,'APPROVER'),($1,'AUDITOR') ON CONFLICT DO NOTHING`, uid)
		return err
	})
}

func (s *Store) Setting(ctx context.Context, key string, out any) (string, error) {
	var raw []byte
	var encrypted string
	err := s.Pool.QueryRow(ctx, `SELECT value_json,encrypted_value FROM settings WHERE key=$1`, key).Scan(&raw, &encrypted)
	if err != nil {
		return "", err
	}
	if out != nil {
		if err = json.Unmarshal(raw, out); err != nil {
			return "", err
		}
	}
	return encrypted, nil
}

func (s *Store) Audit(ctx context.Context, e AuditEvent) error {
	if e.Result == "" {
		e.Result = "SUCCESS"
	}
	before, _ := json.Marshal(e.Before)
	after, _ := json.Marshal(e.After)
	if e.Before == nil {
		before = nil
	}
	if e.After == nil {
		after = nil
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var previous string
	var sequence int64
	err = tx.QueryRow(ctx, `SELECT head_hash,sequence+1 FROM audit_chain_state WHERE id=1 FOR UPDATE`).Scan(&previous, &sequence)
	if err != nil {
		return err
	}
	id := NewID()
	now := time.Now().UTC()
	canonical := strings.Join([]string{fmt.Sprint(sequence), id, now.Format(time.RFC3339Nano), e.UserID, e.EventType, e.TargetType, e.TargetID, e.RequestID, e.Result, string(before), string(after), previous}, "|")
	h := sha256.Sum256([]byte(canonical))
	encodedHash := hex.EncodeToString(h[:])
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs(event_id,timestamp,user_id,user_name,source_ip,session_id,event_type,target_type,target_id,before_value,after_value,request_id,result,previous_hash,canonical_payload,event_hash,chain_sequence) VALUES($1,$2,NULLIF($3,''),$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, id, now, e.UserID, e.UserName, e.SourceIP, e.SessionID, e.EventType, e.TargetType, e.TargetID, before, after, e.RequestID, e.Result, previous, canonical, encodedHash, sequence)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE audit_chain_state SET head_hash=$2,sequence=$3 WHERE id=$1`, 1, encodedHash, sequence); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) Log(ctx context.Context, level, requestID, component, message string, fields any) {
	b, _ := json.Marshal(fields)
	if fields == nil {
		b = []byte(`{}`)
	}
	_, _ = s.Pool.Exec(ctx, `INSERT INTO application_logs(level,request_id,component,message,fields) VALUES($1,$2,$3,$4,$5)`, level, requestID, component, message, b)
}

func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		b[6] = (b[6] & 0x0f) | 0x40 // UUID version 4
		b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
		return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	}
	// crypto/rand failure is exceptionally rare. Keep the service available
	// while retaining process-local uniqueness for identifiers that are always
	// protected by object-level authorization.
	n := time.Now().UTC().UnixNano()
	s := sha256.Sum256([]byte(fmt.Sprintf("%d:%p", n, &n)))
	return fmt.Sprintf("%x-%x-%x-%x-%x", s[0:4], s[4:6], s[6:8], s[8:10], s[10:16])
}
