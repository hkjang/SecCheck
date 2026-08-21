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
