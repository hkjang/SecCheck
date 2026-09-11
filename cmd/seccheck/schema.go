package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/app"
	"github.com/hkjang/SecCheck/internal/store"
)

// A recorded migration is a promise, not a fact. An installation created by
// the very first release recorded version 1 for its own schema.sql, so the
// numbered baseline was skipped forever and two columns added to it later
// never arrived -- the product started cleanly and then failed at the first
// sign-in. An operator had no way to ask whether their database matches the
// build about to run against it, and no way to ask it while locked out of the
// screens that could have told them.
//
// verify-schema builds this build's own migrations into a scratch schema of
// the same database and compares. Exit 0 when they agree, 1 when something the
// application needs is absent, 2 when the check could not be run.
//
// Usage: seccheck verify-schema [--json]
func verifySchema(args []string) int {
	asJSON := false
	for _, arg := range args {
		if arg == "--json" {
			asJSON = true
			continue
		}
		fmt.Fprintf(os.Stderr, "unknown argument %q\n", arg)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cfg, err := app.LoadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	db, err := store.Open(ctx, cfg.PostgresDSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect database: %v\n", err)
		return 2
	}
	defer db.Close()

	missing, unexpected, err := db.SchemaDrift(ctx, cfg.PostgresDSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compare the schema: %v\n", err)
		return 2
	}
	pending, err := db.PendingMigrations(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read applied migrations: %v\n", err)
		return 2
	}
	result := map[string]any{
		"schema_version":     db.SchemaVersion(ctx),
		"pending_migrations": pending,
		"missing":            missing,
		"unexpected":         unexpected,
		"ok":                 len(missing) == 0 && len(pending) == 0,
	}
	if asJSON {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("schema version %d\n", result["schema_version"])
		if len(pending) > 0 {
			fmt.Printf("적용되지 않은 migration %d개: %s\n", len(pending), joinInts(pending))
		}
		for _, line := range missing {
			fmt.Println("없음: " + line)
		}
		for _, line := range unexpected {
			fmt.Println("예상 밖: " + line)
		}
		if result["ok"] == true {
			fmt.Println("데이터베이스가 이 빌드와 일치합니다.")
		} else {
			fmt.Println("데이터베이스가 이 빌드와 다릅니다. 서버를 다시 시작하면 migration이 멱등 적용됩니다; 그래도 남으면 위 목록을 가지고 문의하십시오.")
		}
	}
	if len(missing) > 0 || len(pending) > 0 {
		return 1
	}
	return 0
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, fmt.Sprint(v))
	}
	return strings.Join(parts, ", ")
}
