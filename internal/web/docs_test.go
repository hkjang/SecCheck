package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(body)
}

// Every menu a user can click has to be described in the feature guide the
// README points people at. Four menus shipped without an entry before this
// guard existed, so the drift is not hypothetical.
func TestFeatureGuideCoversEveryMenu(t *testing.T) {
	nav := repoFile(t, "web/src/components/Layout.tsx")
	guide := repoFile(t, "docs/features.md")
	entry := regexp.MustCompile(`\{ to: '([^']+)', label: '([^']+)'`)
	matches := entry.FindAllStringSubmatch(nav, -1)
	if len(matches) < 10 {
		t.Fatalf("parsed only %d nav entries, the Layout.tsx shape must have changed", len(matches))
	}
	for _, m := range matches {
		route, label := m[1], m[2]
		if route == "/" {
			continue // documented as `/`, `/dashboard`
		}
		if !strings.Contains(guide, "(`"+route+"`)") {
			t.Errorf("docs/features.md has no section for the %q menu (%s)", label, route)
		}
	}
}

// Broken image links are worse than no image, and the guide is shipped as a PDF.
func TestFeatureGuideScreenshotsExist(t *testing.T) {
	guide := repoFile(t, "docs/features.md")
	for _, m := range regexp.MustCompile(`!\[[^\]]*\]\(\./(screenshots/[^)]+)\)`).FindAllStringSubmatch(guide, -1) {
		if _, err := os.Stat(filepath.Join("..", "..", "docs", m[1])); err != nil {
			t.Errorf("docs/features.md references a missing screenshot: %s", m[1])
		}
	}
}

// A page that renders nothing until its data arrives owes the reader an
// explanation when the data never comes. Seven pages once left the spinner
// turning for good on a failed first load.
func TestPagesThatBlockOnLoadingAlsoHandleFailure(t *testing.T) {
	pages, err := filepath.Glob(filepath.Join("..", "..", "web", "src", "pages", "*.tsx"))
	if err != nil || len(pages) == 0 {
		t.Fatalf("no pages found: %v", err)
	}
	for _, page := range pages {
		body, err := os.ReadFile(page)
		if err != nil {
			t.Fatalf("read %s: %v", page, err)
		}
		source := string(body)
		if !strings.Contains(source, "return <Loading />") {
			continue
		}
		if !strings.Contains(source, "<LoadFailed") {
			t.Errorf("%s blocks on <Loading /> but never renders <LoadFailed />, so a failed load hangs forever", filepath.Base(page))
		}
	}
}

// An <a href> to an API path hands failure to the browser: a 403, a 409 on
// evidence still being scanned, or a PDF export without the Korean font
// installed all navigate the tab to a JSON problem document. Downloads have
// to go through the fetch helper so the error lands on the page instead.
func TestNoScreenLinksStraightToAnApiDownload(t *testing.T) {
	// Signing in really does hand the browser over to the identity provider.
	allowed := map[string]bool{"/api/v1/auth/oidc/start": true}
	sources, err := filepath.Glob(filepath.Join("..", "..", "web", "src", "pages", "*.tsx"))
	if err != nil {
		t.Fatal(err)
	}
	link := regexp.MustCompile("href=[{\"'`]+(/api/v1[a-zA-Z0-9/_.-]*)")
	for _, source := range sources {
		body, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read %s: %v", source, err)
		}
		for _, m := range link.FindAllStringSubmatch(string(body), -1) {
			if !allowed[m[1]] {
				t.Errorf("%s links straight to %s; use useDownload() so a failed download stays on the page", filepath.Base(source), m[1])
			}
		}
	}
}

// An installation with no internet access cannot look a metric up anywhere
// but its own manual, so every gauge the server emits has to be in it.
func TestEveryMetricIsInTheOperationsManual(t *testing.T) {
	handler := repoFile(t, "internal/web/core_handlers.go")
	manual := repoFile(t, "docs/operations.md")
	names := map[string]bool{}
	for _, m := range regexp.MustCompile(`seccheck_[a-z0-9_]+`).FindAllString(handler, -1) {
		names[m] = true
	}
	if len(names) < 10 {
		t.Fatalf("only %d metric names found; the handler must have changed shape", len(names))
	}
	for name := range names {
		if !strings.Contains(manual, "`"+name+"`") {
			t.Errorf("docs/operations.md never mentions %s, so nobody can write an alert on it", name)
		}
	}
}

// The API guide names required roles per endpoint. When those drift from the
// server they are worse than absent: an integrator plans around a permission
// model the service does not have.
func TestApiGuideRoleColumnMatchesTheServer(t *testing.T) {
	guide := repoFile(t, "docs/api-guide.md")
	server := repoFile(t, "internal/web/server.go")
	registered := map[string]map[string]bool{}
	handle := regexp.MustCompile(`s\.handle\("(\w+)",\s*"([^"]+)",\s*"[^"]*",\s*"[^"]*",\s*(nil|\[\]string\{[^}]*\}),`)
	for _, m := range handle.FindAllStringSubmatch(server, -1) {
		roles := map[string]bool{}
		for _, r := range regexp.MustCompile(`"(\w+)"`).FindAllStringSubmatch(m[3], -1) {
			roles[r[1]] = true
		}
		registered[m[1]+" "+m[2]] = roles
	}
	row := regexp.MustCompile("(?m)^\\| `(GET|POST|PUT|PATCH|DELETE)` \\| `([^`]+)` \\| ([^|]*) \\| ([^|]*) \\|")
	rows := row.FindAllStringSubmatch(guide, -1)
	if len(rows) < 10 {
		t.Fatalf("parsed only %d endpoint rows; the guide's shape must have changed", len(rows))
	}
	for _, m := range rows {
		path := m[2]
		if !strings.HasPrefix(path, "/api") {
			path = "/api/v1" + path
		}
		key := m[1] + " " + path
		roles, known := registered[key]
		if !known {
			t.Errorf("the guide documents %s, which the server does not serve", key)
			continue
		}
		claimed := map[string]bool{}
		for _, r := range regexp.MustCompile("`(\\w+)`").FindAllStringSubmatch(m[4], -1) {
			claimed[r[1]] = true
		}
		// A prose entry such as "해당 심의 참여자" claims no specific role.
		if len(claimed) == 0 {
			continue
		}
		for role := range claimed {
			if !roles[role] {
				t.Errorf("%s: the guide requires %s, the server does not", key, role)
			}
		}
		for role := range roles {
			if !claimed[role] {
				t.Errorf("%s: the server requires %s, the guide omits it", key, role)
			}
		}
	}
}

// An installation that skips many releases applies every migration at once,
// so the operations guide lists what each one does. A migration missing from
// that list is one an operator cannot anticipate.
func TestEveryMigrationIsListedInTheOperationsManual(t *testing.T) {
	manual := repoFile(t, "docs/operations.md")
	files, err := filepath.Glob(filepath.Join("..", "..", "internal", "store", "migrations", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations found: %v", err)
	}
	section := manual
	if start := strings.Index(manual, "### 마이그레이션"); start >= 0 {
		section = manual[start:]
	} else {
		t.Fatal("the operations guide has no migration section")
	}
	for _, file := range files {
		number := filepath.Base(file)[:3]
		// Ranges such as "009~012" cover several files with one row.
		if strings.Contains(section, number) {
			continue
		}
		listed := false
		for _, rang := range regexp.MustCompile(`(\d{3})~(\d{3})`).FindAllStringSubmatch(section, -1) {
			if rang[1] <= number && number <= rang[2] {
				listed = true
			}
		}
		if !listed {
			t.Errorf("migration %s is not described in the operations guide", filepath.Base(file))
		}
	}
}
