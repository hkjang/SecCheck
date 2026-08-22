package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// An installation that runs offline has nobody to call. If the last remaining
// administrator forgets their password, loses their one-time-code device or
// has their account switched off, every route back in goes through another
// administrator -- and there is not one. Restarting does not help: the
// bootstrap account keeps the password it already has.
//
// This is the supported way back, and it deliberately requires what an
// operator has and a user does not: a shell on the host and the database
// credentials. Every change it makes is written to the audit chain, because a
// privileged account being restored out of band is exactly the kind of event a
// later reader must be able to see.
func runAdminRecover(args []string) int {
	var username, password, dsn string
	clearTOTP, unlock, grant := false, false, false
	for i := 0; i < len(args); i++ {
		value := func(flag string) (string, bool) {
			if args[i] == flag && i+1 < len(args) {
				i++
				return args[i], true
			}
			if strings.HasPrefix(args[i], flag+"=") {
				return strings.TrimPrefix(args[i], flag+"="), true
			}
			return "", false
		}
		if v, ok := value("--username"); ok {
			username = v
			continue
		}
		if v, ok := value("--password"); ok {
			password = v
			continue
		}
		if v, ok := value("--dsn"); ok {
			dsn = v
			continue
		}
		switch args[i] {
		case "--clear-totp":
			clearTOTP = true
		case "--unlock":
			unlock = true
		case "--grant-admin":
			grant = true
		case "--help", "-h":
			fmt.Println("usage: seccheck admin-recover --username <name> [--password <new password>] [--clear-totp] [--unlock] [--grant-admin] [--dsn <postgres dsn>]")
			return 0
		default:
			fmt.Fprintf(os.Stderr, "unknown option %q\n", args[i])
			return 2
		}
	}
	if strings.TrimSpace(username) == "" {
		fmt.Fprintln(os.Stderr, "--username is required")
		return 2
	}
	if password == "" && !clearTOTP && !unlock && !grant {
		fmt.Fprintln(os.Stderr, "nothing to do: pass --password, --clear-totp, --unlock or --grant-admin")
		return 2
	}
	if password != "" && len([]rune(password)) < 12 {
		fmt.Fprintln(os.Stderr, "the new password must be at least 12 characters")
		return 2
	}
	if dsn == "" {
		dsn = os.Getenv("POSTGRES_DSN")
	}
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "POSTGRES_DSN is not set and --dsn was not given")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "database: %v\n", err)
		return 1
	}
	defer db.Close()
	changes, err := recoverAdmin(ctx, db, username, password, clearTOTP, unlock, grant)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	fmt.Printf("%s: %s\n", username, strings.Join(changes, ", "))
	fmt.Println("모든 세션이 종료되었습니다. 복구 직후 로그인해 비밀번호를 다시 설정하십시오.")
	return 0
}

// recoverAdmin applies the requested repairs to one local account and says
// what it did. The account has to exist: this tool restores access, it does
// not hand it out.
func recoverAdmin(ctx context.Context, db *store.Store, username, password string, clearTOTP, unlock, grant bool) ([]string, error) {
	var id, source string
	if err := db.Pool.QueryRow(ctx, `SELECT id,auth_source FROM users WHERE username=$1`, username).Scan(&id, &source); err != nil {
		return nil, fmt.Errorf("사용자 %s를 찾을 수 없습니다", username)
	}
	var changes []string
	if password != "" {
		if source != "local" {
			return nil, errors.New("IdP 계정의 비밀번호는 SecCheck에서 관리하지 않습니다")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		if _, err = db.Pool.Exec(ctx, `UPDATE users SET password_hash=$2,active=true,failed_login_count=0,locked_until=NULL,updated_at=now() WHERE id=$1`, id, string(hash)); err != nil {
			return nil, err
		}
		changes = append(changes, "비밀번호 재설정")
	}
	if unlock {
		if _, err := db.Pool.Exec(ctx, `UPDATE users SET active=true,failed_login_count=0,locked_until=NULL,updated_at=now() WHERE id=$1`, id); err != nil {
			return nil, err
		}
		changes = append(changes, "잠금 해제 및 활성화")
	}
	if clearTOTP {
		if _, err := db.Pool.Exec(ctx, `UPDATE users SET totp_secret='',totp_enabled=false,updated_at=now() WHERE id=$1`, id); err != nil {
			return nil, err
		}
		changes = append(changes, "일회용 코드 해제")
	}
	if grant {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_code) VALUES($1,'SYSTEM_ADMIN') ON CONFLICT DO NOTHING`, id); err != nil {
			return nil, err
		}
		changes = append(changes, "SYSTEM_ADMIN 권한 부여")
	}
	// Whatever was repaired, the sessions that existed before it are not the
	// recovered operator's.
	if _, err := db.Pool.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, id); err != nil {
		return nil, err
	}
	if err := db.Audit(ctx, store.AuditEvent{UserID: id, UserName: "cli", EventType: "RECOVER_ADMIN", TargetType: "USER", TargetID: id,
		After: map[string]any{"username": username, "changes": changes}}); err != nil {
		return changes, fmt.Errorf("복구는 적용됐지만 감사 기록에 실패했습니다: %w", err)
	}
	return changes, nil
}
