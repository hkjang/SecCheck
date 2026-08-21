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
