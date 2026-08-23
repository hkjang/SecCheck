package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	_ "time/tzdata" // the image must resolve zone names even without system tzdata

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	Pool *pgxpool.Pool

	auditFailures atomic.Int64

	zoneMu   sync.Mutex
	zoneAt   time.Time
	zoneName string
	zone     *time.Location
}

type User struct {
	ID, Username, DisplayName, Email, Department, PasswordHash, AuthSource string
	Active                                                                 bool
	Roles                                                                  []string
}

type AuditEvent struct {
	UserID, UserName, SourceIP, SessionID, EventType, TargetType, TargetID, RequestID, Result string
	Before, After                                                                             any
}

// Open connects with a pool sized for what this service actually does. The
// driver's default is four connections on a small container, and three
// background workers plus one long export -- an archive or a full chain
// verification can now hold a connection for minutes -- is enough to leave
// every other request queuing behind them. An operator who sets pool_max_conns
// in the DSN has said what they want and is left alone.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(dsn, "pool_max_conns") {
		if headroom := int32(runtime.NumCPU()) * 4; headroom > cfg.MaxConns {
			cfg.MaxConns = headroom
		}
		if cfg.MaxConns < 10 {
			cfg.MaxConns = 10
		}
	}
	if !strings.Contains(dsn, "pool_min_conns") {
		// After a quiet night the first request should not pay for a fresh
		// connection, and an idle pool of two costs nothing.
		cfg.MinConns = 2
	}
	if cfg.ConnConfig.ConnectTimeout == 0 {
		cfg.ConnConfig.ConnectTimeout = 10 * time.Second
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
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

// Location returns the administrator-configured display time zone. Everything
// the server renders or schedules — the daily digest hour, exported
// timestamps, the zone the browser formats in — has to agree on it, otherwise
// a container running UTC quietly shifts an 08:00 digest to 17:00 local.
// Unknown or empty names fall back to UTC rather than to the host zone, so two
// nodes with different host settings still behave identically.
func (s *Store) Location(ctx context.Context) *time.Location {
	s.zoneMu.Lock()
	defer s.zoneMu.Unlock()
	if s.zone != nil && time.Since(s.zoneAt) < time.Minute {
		return s.zone
	}
	var general struct {
		Timezone string `json:"timezone"`
	}
	_, _ = s.Setting(ctx, "general", &general)
	name := strings.TrimSpace(general.Timezone)
	if name == s.zoneName && s.zone != nil {
		s.zoneAt = time.Now()
		return s.zone
	}
	zone := time.UTC
	if name != "" {
		if loaded, err := time.LoadLocation(name); err == nil {
			zone = loaded
		}
	}
	s.zone, s.zoneName, s.zoneAt = zone, name, time.Now()
	return zone
}

// InvalidateLocation drops the cached time zone after the setting changes.
func (s *Store) InvalidateLocation() {
	s.zoneMu.Lock()
	defer s.zoneMu.Unlock()
	s.zone = nil
}

// LocalTime renders a timestamp in the configured zone, for exports and
// e-mails that are read outside the browser.
func (s *Store) LocalTime(ctx context.Context, v any, layout string) string {
	at, ok := AsTime(v)
	if !ok {
		return ""
	}
	return at.In(s.Location(ctx)).Format(layout)
}

// AsTime accepts the shapes a timestamp arrives in: a time.Time from pgx, or
// an RFC3339 string once it has been through JSON.
func AsTime(v any) (time.Time, bool) {
	switch value := v.(type) {
	case time.Time:
		return value, true
	case *time.Time:
		if value == nil {
			return time.Time{}, false
		}
		return *value, true
	case string:
		if value == "" {
			return time.Time{}, false
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
			if at, err := time.Parse(layout, value); err == nil {
				return at, true
			}
		}
	}
	return time.Time{}, false
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

// UpsertBootstrap makes sure the account named by BOOTSTRAP_ADMIN exists and
// can always administer the installation. A first run gets every role so the
// appliance is usable out of the box; a restart restores only SYSTEM_ADMIN.
//
// It used to re-grant all six roles on every start, which quietly undid the
// separation the administration guide asks for: an operator who moves the
// reviewer role off the shared admin account -- so that account cannot review
// what it requested -- found it back after the next restart, and nothing said
// so.
func (s *Store) UpsertBootstrap(ctx context.Context, id, username, passwordHash string) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var uid string
		var created bool
		if err := tx.QueryRow(ctx, `INSERT INTO users(id,username,display_name,password_hash,auth_source) VALUES($1,$2,$2,$3,'local') ON CONFLICT(username) DO UPDATE SET password_hash=CASE WHEN users.password_hash='' THEN EXCLUDED.password_hash ELSE users.password_hash END,active=true,updated_at=now() RETURNING id,(xmax=0)`, id, username, passwordHash).Scan(&uid, &created); err != nil {
			return err
		}
		roles := []string{"SYSTEM_ADMIN"}
		if created {
			roles = append(roles, "TEMPLATE_ADMIN", "SECURITY_REVIEWER", "REQUESTER", "APPROVER", "AUDITOR")
		}
		_, err := tx.Exec(ctx, `INSERT INTO user_roles(user_id,role_code) SELECT $1,unnest($2::text[]) ON CONFLICT DO NOTHING`, uid, roles)
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

// Audit appends one event to the hash chain. Callers discard the error --
// the action they are recording has already happened, so refusing the request
// would be a lie -- which means a failure here would otherwise vanish: the
// chain still verifies, because it is consistent with what it contains, and
// nothing says an event is missing from it. For a service whose whole claim
// is a tamper-evident record, losing events quietly is the worst outcome
// available, so every failure is counted, logged, and left on standard error
// where it survives the database being the thing that broke.
func (s *Store) Audit(ctx context.Context, e AuditEvent) error {
	err := s.appendAudit(ctx, e)
	if err != nil {
		s.auditFailures.Add(1)
		slog.Error("audit event could not be recorded", "event_type", e.EventType, "target_type", e.TargetType,
			"target_id", e.TargetID, "user", e.UserName, "error", err)
		s.Log(ctx, "ERROR", e.RequestID, "audit", "감사 이벤트를 기록하지 못했습니다.",
			map[string]any{"event_type": e.EventType, "target_type": e.TargetType, "target_id": e.TargetID, "error": err.Error()})
	}
	return err
}

// AuditFailures counts events lost since the process started. It is in memory
// on purpose: the database is exactly what may be unavailable when it grows.
func (s *Store) AuditFailures() int64 { return s.auditFailures.Load() }

func (s *Store) appendAudit(ctx context.Context, e AuditEvent) error {
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
	if _, err := s.Pool.Exec(ctx, `INSERT INTO application_logs(level,request_id,component,message,fields) VALUES($1,$2,$3,$4,$5)`, level, requestID, component, message, b); err != nil {
		// Structured logs live in the database, so a database fault would
		// otherwise erase the record of itself -- the one failure where the
		// log matters most is the one it cannot write down. Standard error
		// is the only place left that a container log collector still reads.
		slog.Error("application log could not be stored", "level", level, "component", component, "message", message,
			"fields", string(b), "request_id", requestID, "error", err)
	}
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
