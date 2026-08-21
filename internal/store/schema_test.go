package store_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Four times now a column or setting has shipped that nothing ever read: the
// retention window, the display time zone, the per-item assignee, and the
// physical-file retention the comments claimed existed. Each looked like a
// working feature in the console and did nothing. This walks the schema and
// the settings defaults and fails on anything the Go source never mentions.
func TestSchemaAndSettingsHaveNoDeadEntries(t *testing.T) {
	root := filepath.Join("..", "..")
	source := goSource(t, root)

	for name, columns := range schemaColumns(t, filepath.Join(root, "internal", "store", "migrations")) {
		for _, column := range columns {
			if !mentions(source, column) {
				t.Errorf("%s.%s is declared in the schema but never referenced in Go", name, column)
			}
		}
	}
	for _, key := range settingsKeys(t, filepath.Join(root, "internal", "store", "migrations")) {
		if !mentions(source, key) {
			t.Errorf("setting %q ships in the defaults but is never read in Go", key)
		}
	}
}

func mentions(source, word string) bool {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(word) + `\b`).MatchString(source)
}

func goSource(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			body, readErr := os.ReadFile(path)
			if readErr == nil {
				b.Write(body)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return b.String()
}

var (
	createTable = regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS (\w+) \((.*?)\n\);`)
	addColumn   = regexp.MustCompile(`ALTER TABLE (\w+) ADD COLUMN IF NOT EXISTS (\w+)`)
	dropColumn  = regexp.MustCompile(`ALTER TABLE (\w+) DROP COLUMN IF EXISTS (\w+)`)
	columnName  = regexp.MustCompile(`^[a-z_]+$`)
	settingsRow = regexp.MustCompile(`'(\{[^']*\})'::jsonb`)
	jsonKey     = regexp.MustCompile(`"([a-z_]+)"\s*:`)
)

var notColumns = map[string]bool{"primary": true, "unique": true, "foreign": true, "check": true, "constraint": true}

func schemaColumns(t *testing.T, dir string) map[string][]string {
	t.Helper()
	tables := map[string]map[string]bool{}
	for _, body := range migrationBodies(t, dir) {
		for _, m := range createTable.FindAllStringSubmatch(body, -1) {
			table := m[1]
			if tables[table] == nil {
				tables[table] = map[string]bool{}
			}
			for _, line := range strings.Split(m[2], "\n") {
				field := strings.SplitN(strings.TrimSpace(line), " ", 2)[0]
				if columnName.MatchString(field) && !notColumns[field] {
					tables[table][field] = true
				}
			}
		}
		for _, m := range addColumn.FindAllStringSubmatch(body, -1) {
			if tables[m[1]] == nil {
				tables[m[1]] = map[string]bool{}
			}
			tables[m[1]][m[2]] = true
		}
		for _, m := range dropColumn.FindAllStringSubmatch(body, -1) {
			delete(tables[m[1]], m[2])
		}
	}
	out := map[string][]string{}
	for table, columns := range tables {
		for column := range columns {
			out[table] = append(out[table], column)
		}
	}
	return out
}

func settingsKeys(t *testing.T, dir string) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, body := range migrationBodies(t, dir) {
		for _, line := range strings.Split(body, "\n") {
			if !strings.Contains(line, "settings") && !strings.Contains(line, "value_json") {
				continue
			}
			for _, m := range settingsRow.FindAllStringSubmatch(line, -1) {
				for _, key := range jsonKey.FindAllStringSubmatch(m[1], -1) {
					seen[key[1]] = true
				}
			}
		}
	}
	var out []string
	for key := range seen {
		out = append(out, key)
	}
	return out
}

func migrationBodies(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var bodies []string
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		bodies = append(bodies, string(body))
	}
	if len(bodies) == 0 {
		t.Fatal("no migrations found")
	}
	return bodies
}
