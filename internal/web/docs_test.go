package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

// A pinned action's comment names the upstream release the digest belongs to.
// Bumping the product version with a blanket replace across the workflow files
// rewrote those comments too, so the pins claimed a version their upstream had
// never released -- and anyone auditing the digest read a lie.
func TestPinnedActionsDoNotClaimTheProductVersion(t *testing.T) {
	version := strings.TrimSpace(repoFile(t, "VERSION"))
	pin := regexp.MustCompile(`uses: ([^\s@]+)@[0-9a-f]{40} # (v[^\s]+)`)
	files, err := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflow files: %v", err)
	}
	for _, file := range files {
		for _, m := range pin.FindAllStringSubmatch(repoFile(t, filepath.Join(".github", "workflows", filepath.Base(file))), -1) {
			if strings.TrimPrefix(m[2], "v") == version {
				t.Errorf("%s pins %s as %s, which is SecCheck's own version -- the comment was overwritten by a version bump", filepath.Base(file), m[1], m[2])
			}
		}
	}
}

// The release version lives in five files that are bumped by hand. A bump that
// misses one ships an image tagged as the previous release, or a README that
// tells an operator to pull a tag that was never built.
func TestReleaseVersionIsTheSameEverywhere(t *testing.T) {
	version := strings.TrimSpace(repoFile(t, "VERSION"))
	for _, file := range []string{"compose.yaml", "README.md", filepath.Join(".github", "workflows", "ci.yml"), filepath.Join("web", "package.json")} {
		body := repoFile(t, file)
		found := false
		for _, m := range regexp.MustCompile(`(?:seccheck:v|Release-v|VERSION=|"version": ")(\d+\.\d+\.\d+)`).FindAllStringSubmatch(body, -1) {
			found = true
			if m[1] != version {
				t.Errorf("%s names version %s but VERSION says %s", file, m[1], version)
			}
		}
		if !found {
			t.Errorf("%s no longer carries the release version -- the guard cannot see a missed bump", file)
		}
	}
}

// A release that changes how an installation behaves carries a 주의 section in
// the changelog. Those are exactly the entries an operator upgrading across
// many versions has to find, and the place they look is the upgrade table --
// which the notes had drifted a dozen releases behind.
func TestEveryWarnedReleaseIsInTheUpgradeTable(t *testing.T) {
	changelog := repoFile(t, "CHANGELOG.md")
	guide := repoFile(t, filepath.Join("docs", "operations.md"))
	table := guide[strings.Index(guide, "## 여러 버전을 건너뛰어 올라올 때"):]
	if !strings.Contains(guide, "## 여러 버전을 건너뛰어 올라올 때") {
		t.Fatal("the operations guide has no upgrade table")
	}
	version := ""
	warned := []string{}
	for _, line := range strings.Split(changelog, "\n") {
		if strings.HasPrefix(line, "## v") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "## "))
		}
		if strings.HasPrefix(line, "### 주의") && version != "" {
			warned = append(warned, version)
		}
	}
	if len(warned) < 3 {
		t.Fatalf("only %d warned releases found; the changelog must have changed shape", len(warned))
	}
	for _, release := range warned {
		if !strings.Contains(table, "| "+release+" ") && !strings.Contains(table, "| "+release+"~") {
			t.Errorf("%s carries a 주의 note but is not in the upgrade table, so an operator skipping versions will not see it", release)
		}
	}
}

// The API guide presents its MCP tool list as the list, so a tool missing from
// it is a tool an integrator never learns exists -- they would have to call
// tools/list to find out. Two were missing when this was written.
func TestEveryMCPToolIsInTheAPIGuide(t *testing.T) {
	guide := repoFile(t, filepath.Join("docs", "api-guide.md"))
	named := map[string]bool{}
	for _, tool := range mcpTools() {
		name, _ := tool["name"].(string)
		if name == "" {
			t.Fatal("a tool in the catalogue has no name")
		}
		named[name] = true
		if !strings.Contains(guide, "`"+name+"`") {
			t.Errorf("%s is offered over MCP but is not in docs/api-guide.md", name)
		}
	}
	if len(named) < 5 {
		t.Fatalf("only %d tools found; the catalogue must have changed shape", len(named))
	}
	for _, match := range regexp.MustCompile("`(seccheck\\.[a-z_]+)`").FindAllStringSubmatch(guide, -1) {
		if !named[match[1]] {
			t.Errorf("docs/api-guide.md documents %s, which the server does not offer", match[1])
		}
	}
}

// A control whose only content is an icon has no name for a screen reader, and
// no tooltip for anyone hovering it. Most of the product already labels them;
// five did not, so the rule is written down rather than remembered.
func TestIconOnlyControlsHaveANameToRead(t *testing.T) {
	pages, err := filepath.Glob(filepath.Join("..", "..", "web", "src", "**", "*.tsx"))
	if err != nil {
		t.Fatal(err)
	}
	more, _ := filepath.Glob(filepath.Join("..", "..", "web", "src", "*", "*.tsx"))
	pages = append(pages, more...)
	if len(pages) < 10 {
		t.Fatalf("only %d screens found; the layout must have changed", len(pages))
	}
	// The attribute list can contain => inside a handler, so the opening tag is
	// scanned with brace awareness rather than up to the first >.
	onlyIcons := regexp.MustCompile(`^(?:\s*<[A-Z][A-Za-z0-9]*(?:\s[^<>]*)?/>\s*)+$`)
	opening := regexp.MustCompile(`<(Button|button)\b`)
	for _, page := range pages {
		body, err := os.ReadFile(page)
		if err != nil {
			continue
		}
		src := string(body)
		for _, m := range opening.FindAllStringIndex(src, -1) {
			i, depth := m[1], 0
			for i < len(src) {
				switch src[i] {
				case '{':
					depth++
				case '}':
					depth--
				case '>':
					if depth == 0 {
						goto found
					}
				}
				i++
			}
		found:
			if i >= len(src) {
				continue
			}
			tag := src[m[0]:i]
			name := "Button"
			if strings.HasPrefix(src[m[0]:], "<button") {
				name = "button"
			}
			close := strings.Index(src[i:], "</"+name+">")
			if close < 0 {
				continue
			}
			inner := src[i+1 : i+close]
			if !onlyIcons.MatchString(inner) || strings.Contains(tag, "aria-label") || strings.Contains(tag, "title=") {
				continue
			}
			t.Errorf("%s has a control showing only %s with no aria-label or title", filepath.Base(page), strings.TrimSpace(inner))
		}
	}
}

// The label of a field has to be attached to the control it names, or a screen
// reader announces an unnamed box and clicking the label does nothing. The
// association lives in one component, so this checks that it is still there.
func TestFieldLabelsAreAttachedToTheirControl(t *testing.T) {
	ui := repoFile(t, filepath.Join("web", "src", "components", "ui.tsx"))
	start := strings.Index(ui, "export function Field(")
	if start < 0 {
		t.Fatal("the Field component is gone; this test needs rewriting")
	}
	end := strings.Index(ui[start:], "\nexport function ")
	if end < 0 {
		end = len(ui) - start
	}
	field := ui[start : start+end]
	for _, needed := range []string{"htmlFor", "useId", "aria-describedby", "aria-invalid"} {
		if !strings.Contains(field, needed) {
			t.Errorf("Field no longer uses %s, so its label and messages are not attached to the control", needed)
		}
	}
}

// Every dialog in the product comes from one component, so what it does for a
// keyboard user is decided in one place: it has to announce itself as a
// dialog, take focus when it opens, keep Tab inside it and give focus back
// when it closes.
func TestDialogsTakeFocusAndSayWhatTheyAre(t *testing.T) {
	ui := repoFile(t, filepath.Join("web", "src", "components", "ui.tsx"))
	start := strings.Index(ui, "export function Modal(")
	if start < 0 {
		t.Fatal("the Modal component is gone; this test needs rewriting")
	}
	end := strings.Index(ui[start:], "\ntype ")
	if end < 0 {
		end = len(ui) - start
	}
	modal := ui[start : start+end]
	for behaviour, marker := range map[string]string{
		"announce itself as a dialog":  `role="dialog"`,
		"hide the page behind it":      `aria-modal="true"`,
		"take focus when it opens":     ".focus()",
		"keep Tab inside it":           "e.key !== 'Tab'",
		"close on Escape":              "'Escape'",
		"give focus back when it goes": "opener?.focus",
	} {
		if !strings.Contains(modal, marker) {
			t.Errorf("Modal no longer seems to %s (%s is missing)", behaviour, marker)
		}
	}
}

// A screen that builds its own dialog out of the backdrop markup misses
// everything the shared component does for a keyboard user, and nobody
// notices until somebody tries to use it that way.
func TestNoScreenBuildsItsOwnDialog(t *testing.T) {
	pages, err := filepath.Glob(filepath.Join("..", "..", "web", "src", "pages", "*.tsx"))
	if err != nil || len(pages) == 0 {
		t.Fatalf("no screens found: %v", err)
	}
	for _, page := range pages {
		body, err := os.ReadFile(page)
		if err != nil {
			continue
		}
		if strings.Contains(string(body), `className="modal-backdrop"`) {
			t.Errorf("%s builds its own dialog; use the Modal component so it takes focus and announces itself", filepath.Base(page))
		}
	}
}

// Toasts are how the product says whether anything worked. One that is not
// announced leaves somebody who cannot see it with no way to know whether the
// save happened, and the same goes for the spinner that says work is running.
func TestTheProductAnnouncesWhatItIsDoing(t *testing.T) {
	ui := repoFile(t, filepath.Join("web", "src", "components", "ui.tsx"))
	toast := ui[strings.Index(ui, "export function ToastProvider"):]
	if end := strings.Index(toast, "\nexport const useToast"); end > 0 {
		toast = toast[:end]
	}
	if !strings.Contains(toast, "aria-live") {
		t.Error("toasts are not in a live region, so nothing announces them")
	}
	if !strings.Contains(toast, `role={item.kind === 'error' ? 'alert' : 'status'}`) {
		t.Error("a toast does not carry a role, so its urgency is not conveyed")
	}
	loading := ui[strings.Index(ui, "export function Loading"):]
	if end := strings.Index(loading, "\n"); end > 0 {
		loading = loading[:end]
	}
	if !strings.Contains(loading, `role="status"`) {
		t.Error("the loading state has no role, so aria-label on its div is ignored")
	}
}

// A notification that names no target leaves the reader with nowhere to go
// unless the screen knows where that kind of alert belongs. Every such event
// therefore has to appear in the notification screen's destination map.
func TestNotificationsWithoutATargetHaveSomewhereToGo(t *testing.T) {
	page := repoFile(t, filepath.Join("web", "src", "pages", "Notifications.tsx"))
	sources := []string{"internal/maintenance/worker.go", "internal/scanner/worker.go", "internal/web/admin.go", "internal/web/reviews.go"}
	targetless := regexp.MustCompile(`Notify\(ctx, [A-Za-z0-9_.]+, "([A-Z_]{3,})"[^)]*, "", ""\)`)
	checked := 0
	for _, file := range sources {
		body, err := os.ReadFile(filepath.Join("..", "..", file))
		if err != nil {
			continue
		}
		for _, m := range targetless.FindAllStringSubmatch(string(body), -1) {
			checked++
			if !strings.Contains(page, m[1]+":") {
				t.Errorf("%s is sent with no target and has no destination on the notification screen", m[1])
			}
		}
	}
	if checked == 0 {
		t.Fatal("the scan found no target-less notifications; the call shape must have changed")
	}
}

// A row that only a mouse can open is a row a keyboard user cannot read. The
// checklist row -- the most used control in the product -- was a plain div with
// an onClick: everything inside it was reachable by keyboard except the one
// action that reveals it. Every clickable container has to carry either its own
// keyboard handling or a real control that does the same thing.
func TestClickableRowsCanBeOperatedFromTheKeyboard(t *testing.T) {
	pages, err := filepath.Glob(filepath.Join("..", "..", "web", "src", "*", "*.tsx"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) < 10 {
		t.Fatalf("only %d screens found; the layout must have changed", len(pages))
	}
	clickable := regexp.MustCompile(`(?s)<(div|span|article|li|tr|td)\b[^>]{0,400}?onClick`)
	for _, page := range pages {
		body, err := os.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		for _, m := range clickable.FindAllString(text, -1) {
			// onFocusCapture covers a container that only records which item
			// the user is working on: tabbing into its fields is the keyboard
			// equivalent of clicking it.
			if strings.Contains(m, "onKeyDown") || strings.Contains(m, "tabIndex") || strings.Contains(m, "role=") || strings.Contains(m, "onFocusCapture") {
				continue
			}
			// Otherwise the same block has to offer a focusable control for the
			// action, which is what aria-expanded on a button marks.
			if strings.Contains(text, "aria-expanded") {
				continue
			}
			t.Errorf("%s: a container reacts to a click with no keyboard equivalent:\n%s", filepath.Base(page), strings.TrimSpace(m))
		}
	}
}

// The upgrade table is what an offline installation reads when it jumps many
// releases at once, and it is the first document to fall behind: it stopped at
// v0.98.0 while the product shipped forty-eight more releases, several of which
// changed what an operator's alerts and scripts see. The leash is crude on
// purpose -- it says the table has been looked at recently, not what it says.
func TestTheUpgradeTableKeepsUpWithTheReleases(t *testing.T) {
	manual := repoFile(t, "docs/operations.md")
	version := strings.TrimSpace(repoFile(t, "VERSION"))
	current := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`).FindStringSubmatch(version)
	if current == nil {
		t.Fatalf("VERSION is %q, which this guard cannot read", version)
	}
	section := manual[strings.Index(manual, "## 여러 버전을 건너뛰어 올라올 때"):]
	if cut := strings.Index(section, "### 마이그레이션"); cut > 0 {
		section = section[:cut]
	}
	newest := -1
	for _, m := range regexp.MustCompile(`v(\d+)\.(\d+)\.(\d+)`).FindAllStringSubmatch(section, -1) {
		if m[1] != current[1] || m[2] != current[2] {
			continue
		}
		if patch, err := strconv.Atoi(m[3]); err == nil && patch > newest {
			newest = patch
		}
	}
	if newest < 0 {
		t.Fatalf("the upgrade table names no release on the current %s.%s line", current[1], current[2])
	}
	patch, err := strconv.Atoi(current[3])
	if err != nil {
		t.Fatal(err)
	}
	if patch-newest > 20 {
		t.Errorf("the upgrade table stops at %s.%s.%d while the product is at %s: an offline installation skipping these releases is told nothing about them",
			current[1], current[2], newest, version)
	}
}
