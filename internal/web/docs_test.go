package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

// The release version lives in six files that are bumped by hand. A bump that
// misses one ships an image tagged as the previous release, or a README that
// tells an operator to pull a tag that was never built. The admin guide names
// the archive an offline site is handed, so it is one of the six.
func TestReleaseVersionIsTheSameEverywhere(t *testing.T) {
	version := strings.TrimSpace(repoFile(t, "VERSION"))
	for _, file := range []string{"compose.yaml", "README.md", filepath.Join(".github", "workflows", "ci.yml"), filepath.Join("web", "package.json"), filepath.Join("docs", "ADMIN_GUIDE.md")} {
		body := repoFile(t, file)
		found := false
		for _, m := range regexp.MustCompile(`(?:seccheck:v|seccheck-v|Release-v|VERSION=|"version": ")(\d+\.\d+\.\d+)`).FindAllStringSubmatch(body, -1) {
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

// The only release asset is the image archive, so an operator on a closed
// network has no way to fetch compose.yaml from the repository. The admin
// guide's install section carries the file in full instead -- and a copy that
// is not the file is worse than a link, because the guide promises it can be
// saved and started as is.
func TestAdminGuideCarriesTheComposeFile(t *testing.T) {
	guide := repoFile(t, filepath.Join("docs", "ADMIN_GUIDE.md"))
	blocks := regexp.MustCompile("(?s)```yaml\n(.*?)```").FindAllStringSubmatch(guide, -1)
	if len(blocks) == 0 {
		t.Fatal("docs/ADMIN_GUIDE.md has no yaml block; the install section no longer carries compose.yaml")
	}
	compose := repoFile(t, "compose.yaml")
	for _, block := range blocks {
		if block[1] == compose {
			return
		}
	}
	t.Errorf("no yaml block in docs/ADMIN_GUIDE.md matches compose.yaml -- paste the file into section 2-4 again")
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

// The upgrade table keeps telling integrators their scripts need changing, and
// those scripts branch on error.code -- which was written down nowhere, so the
// only way to learn the codes was to read the server. Every code the server
// returns has to be in the guide, and the guide must not invent any.
func TestEveryErrorCodeIsInTheApiGuide(t *testing.T) {
	guide := repoFile(t, "docs/api-guide.md")
	emitted := map[string]bool{}
	for _, dir := range []string{filepath.Join("..", "..", "internal"), filepath.Join("..", "..", "cmd")} {
		err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			for _, m := range regexp.MustCompile(`problem\(w,\s*(?:http\.Status\w+|\d+),\s*"([A-Z_]{3,})"`).FindAllStringSubmatch(string(body), -1) {
				emitted[m[1]] = true
			}
			for _, m := range regexp.MustCompile(`\bfault\(w, r, "([A-Z_]{3,})"`).FindAllStringSubmatch(string(body), -1) {
				emitted[m[1]] = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if len(emitted) < 30 {
		t.Fatalf("only %d error codes found; the handlers must have changed shape", len(emitted))
	}
	documented := map[string]bool{}
	for _, m := range regexp.MustCompile("`([A-Z_]{3,})`").FindAllStringSubmatch(guide, -1) {
		documented[m[1]] = true
	}
	for code := range emitted {
		if !documented[code] {
			t.Errorf("the server returns %s and docs/api-guide.md never mentions it, so an integration cannot branch on it", code)
		}
	}
}

// A screen that fetches on mount has three states, and it used to render two:
// a spinner while it waits and the empty state when the answer is empty. A
// request that failed left the spinner turning for good on the busiest lists,
// and on the ones that toasted the error the toast faded and the spinner
// stayed -- an administrator searching for an account was shown "조건에 맞는
// 사용자가 없습니다" or a spinner where the honest answer was "불러오지
// 못했습니다".
func TestAScreenThatFetchesOnMountCanSayItFailed(t *testing.T) {
	pages, err := filepath.Glob(filepath.Join("..", "..", "web", "src", "pages", "*.tsx"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) < 10 {
		t.Fatalf("only %d screens found; the layout must have changed", len(pages))
	}
	checked := 0
	for _, page := range pages {
		body, err := os.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		// A screen that reads the API through the typed helper and has an
		// effect to run it on arrival is a screen with something to load.
		if !strings.Contains(text, "get<") || !strings.Contains(text, "useEffect(") {
			continue
		}
		checked++
		if !strings.Contains(text, "LoadFailed") {
			t.Errorf("%s fetches on mount and has no way to say the request failed", filepath.Base(page))
		}
	}
	if checked < 15 {
		t.Fatalf("only %d screens were found to fetch on mount; the check is not reading the pages", checked)
	}
}

// The pre-push script exists to say what the pipeline will say. It can only do
// that while it runs the same scanner: a second copy of the pinned digest
// would drift, and then the script would be checking something the pipeline no
// longer runs -- worse than no script, because people would trust it.
func TestThePrePushScriptUsesThePipelinesOwnScanner(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "precheck.sh"))
	if err != nil {
		t.Fatalf("the pre-push script is missing: %v", err)
	}
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	pinned := regexp.MustCompile(`ghcr\.io/gitleaks/gitleaks@sha256:[0-9a-f]{64}`)
	if !pinned.Match(workflow) {
		t.Fatal("the pipeline no longer pins the secret scanner by digest")
	}
	if pinned.Match(script) {
		t.Error("the script carries its own copy of the scanner digest, which will drift from the pipeline's")
	}
	// It has to read the pin from the workflow, which is the only way the two
	// can stay the same thing.
	if !strings.Contains(string(script), ".github/workflows/ci.yml") {
		t.Error("the script does not take the scanner from the workflow")
	}
	// And both have to look at the same thing: the tree, not one commit.
	for name, body := range map[string]string{"ci.yml": string(workflow), "precheck.sh": string(script)} {
		if strings.Contains(body, "gitleaks") && !strings.Contains(body, "--no-git") {
			t.Errorf("%s scans a commit rather than the tree that will be shipped", name)
		}
	}
}

// The admin guide says its environment-variable table is everything the
// runtime reads, and an operator on a closed network has nowhere else to look
// it up. A variable the code reads but the table omits is one nobody sets; a
// variable the table names but nothing reads is one somebody sets in vain.
func TestAdminGuideEnvVarTableIsEverythingTheCodeReads(t *testing.T) {
	guide := repoFile(t, filepath.Join("docs", "ADMIN_GUIDE.md"))
	start := strings.Index(guide, "### 3-1. 환경 변수")
	if start < 0 {
		t.Fatal("docs/ADMIN_GUIDE.md has no environment variable section")
	}
	section := guide[start:]
	if end := strings.Index(section, "\n### "); end > 0 {
		section = section[:end]
	}
	documented := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\| `([A-Z][A-Z0-9_]*)` \\|").FindAllStringSubmatch(section, -1) {
		documented[m[1]] = true
	}
	if len(documented) < 4 {
		t.Fatalf("parsed only %d rows from the environment variable table; its shape must have changed", len(documented))
	}
	read := map[string]string{}
	call := regexp.MustCompile(`os\.(?:Getenv|LookupEnv)\("([A-Z][A-Z0-9_]*)"\)`)
	for _, dir := range []string{filepath.Join("..", "..", "internal"), filepath.Join("..", "..", "cmd")} {
		err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// The test database helper is compiled into the tests only.
			if strings.Contains(path, string(filepath.Separator)+"testdb"+string(filepath.Separator)) {
				return nil
			}
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			for _, m := range call.FindAllStringSubmatch(string(body), -1) {
				read[m[1]] = filepath.ToSlash(strings.TrimPrefix(path, filepath.Join("..", "..")+string(filepath.Separator)))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if len(read) < 4 {
		t.Fatalf("only %d environment variables found in the code; the call shape must have changed", len(read))
	}
	for name, file := range read {
		if !documented[name] {
			t.Errorf("%s reads %s and the admin guide's table does not list it", file, name)
		}
	}
	for name := range documented {
		if _, ok := read[name]; !ok {
			t.Errorf("the admin guide lists %s, which nothing in the code reads", name)
		}
	}
}

// The service settings tables in the admin guide name every key a tab holds
// and the value a fresh installation starts with. Those defaults live in the
// migration seeds and, for keys the seeds never wrote, in the screen's own
// fallback -- so the guide is checked against both, in both directions. It had
// filed the deleted-evidence retention under the wrong tab when this was
// written.
func TestAdminGuideSettingsTablesMatchTheSeedsAndTheScreen(t *testing.T) {
	// Seeds: the first value a migration writes for a key is the default,
	// because every later write is `'{...}'::jsonb || value_json`, which only
	// fills keys that are still missing.
	files, err := filepath.Glob(filepath.Join("..", "..", "internal", "store", "migrations", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations found: %v", err)
	}
	sort.Strings(files)
	seeded := map[string]map[string]any{}
	insert := regexp.MustCompile(`\('(\w+)',\s*'(\{[^']*\})'::jsonb`)
	fill := regexp.MustCompile(`UPDATE settings SET value_json = '(\{[^']*\})'::jsonb \|\| value_json WHERE key\s*=\s*'(\w+)'`)
	remember := func(tab, literal string) {
		var values map[string]any
		if err := json.Unmarshal([]byte(literal), &values); err != nil {
			t.Fatalf("settings seed for %s is not JSON: %v", tab, err)
		}
		if seeded[tab] == nil {
			seeded[tab] = map[string]any{}
		}
		for key, value := range values {
			if _, done := seeded[tab][key]; !done {
				seeded[tab][key] = value
			}
		}
	}
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range insert.FindAllStringSubmatch(string(body), -1) {
			remember(m[1], m[2])
		}
		for _, m := range fill.FindAllStringSubmatch(string(body), -1) {
			remember(m[2], m[1])
		}
	}
	if len(seeded) < 5 {
		t.Fatalf("only %d settings tabs are seeded; the migration shape must have changed", len(seeded))
	}

	// The screen: which keys each tab edits, and what it shows when the value
	// has never been saved.
	screen := repoFile(t, filepath.Join("web", "src", "pages", "Settings.tsx"))
	onScreen := map[string]map[string]bool{}
	fallback := map[string]string{}
	parts := strings.Split(screen, "{tab === '")
	for _, part := range parts[1:] {
		tab := part[:strings.Index(part, "'")]
		onScreen[tab] = map[string]bool{}
		for _, m := range regexp.MustCompile(`draft\.([a-z_]+)`).FindAllStringSubmatch(part, -1) {
			onScreen[tab][m[1]] = true
		}
		for _, m := range regexp.MustCompile(`draft\.([a-z_]+) (?:\?\?|\|\|) ('[^']*'|\d+)\)`).FindAllStringSubmatch(part, -1) {
			fallback[m[1]] = strings.Trim(m[2], "'")
		}
		for _, m := range regexp.MustCompile(`draft\.([a-z_]+) !== false`).FindAllStringSubmatch(part, -1) {
			fallback[m[1]] = "true"
		}
	}
	if len(onScreen) < 5 {
		t.Fatalf("only %d tabs found on the settings screen; its shape must have changed", len(onScreen))
	}

	// The guide renders a default the way an operator reads it.
	var render func(value any) string
	render = func(value any) string {
		switch v := value.(type) {
		case string:
			if v == "" {
				return "(비어 있음)"
			}
			return v
		case bool:
			return strconv.FormatBool(v)
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		case []any:
			if len(v) == 0 {
				return "(비어 있음)"
			}
			words := make([]string, 0, len(v))
			for _, item := range v {
				words = append(words, render(item))
			}
			return strings.Join(words, " ")
		}
		return ""
	}

	guide := repoFile(t, filepath.Join("docs", "ADMIN_GUIDE.md"))
	start := strings.Index(guide, "### 3-2. 서비스 설정 화면")
	if start < 0 {
		t.Fatal("docs/ADMIN_GUIDE.md has no service settings section")
	}
	section := guide[start:]
	if end := strings.Index(section, "\n### "); end > 0 {
		section = section[:end]
	}
	heading := regexp.MustCompile("(?m)^\\*\\*[^*]+ \\(`([a-z]+)`\\)\\*\\*")
	row := regexp.MustCompile("(?m)^\\| [^|]+ \\| ((?:`[a-z_]+`(?: / )?)+) \\| ([^|]*) \\|")
	documented := map[string]map[string]bool{}
	marks := heading.FindAllStringSubmatchIndex(section, -1)
	for i, mark := range marks {
		tab := section[mark[2]:mark[3]]
		end := len(section)
		if i+1 < len(marks) {
			end = marks[i+1][0]
		}
		documented[tab] = map[string]bool{}
		for _, m := range row.FindAllStringSubmatch(section[mark[1]:end], -1) {
			keys := regexp.MustCompile("`([a-z_]+)`").FindAllStringSubmatch(m[1], -1)
			defaults := strings.Split(m[2], " / ")
			for j, k := range keys {
				key := k[1]
				documented[tab][key] = true
				if _, isSeeded := seeded[tab][key]; !isSeeded && !onScreen[tab][key] {
					t.Errorf("the guide files %s under the %s tab, and neither the seeds nor the screen put it there", key, tab)
					continue
				}
				expected, known := "", false
				if value, ok := seeded[tab][key]; ok {
					expected, known = render(value), true
				} else if value, ok := fallback[key]; ok {
					expected, known = render(value), true
				}
				if !known {
					continue
				}
				shown := defaults[0]
				if j < len(defaults) {
					shown = defaults[j]
				}
				shown = strings.Trim(strings.TrimSpace(shown), "`")
				if shown != expected {
					t.Errorf("the guide says %s starts as %q, the code says %q", key, shown, expected)
				}
			}
		}
	}
	if len(documented) < 5 {
		t.Fatalf("only %d settings tabs are documented; the guide's shape must have changed", len(documented))
	}
	for tab, keys := range seeded {
		if documented[tab] == nil {
			continue // Keycloak OIDC is walked through as prose in 3-3.
		}
		for key := range keys {
			if !documented[tab][key] {
				t.Errorf("the %s tab is seeded with %s and the guide never lists it", tab, key)
			}
		}
	}
	for tab, keys := range onScreen {
		if documented[tab] == nil {
			continue
		}
		for key := range keys {
			if !documented[tab][key] {
				t.Errorf("the %s tab edits %s and the guide never lists it", tab, key)
			}
		}
	}
}

// guideSection returns the body of one heading in a guide, up to the next
// heading of the same or a higher level.
func guideSection(t *testing.T, guide, heading string) string {
	t.Helper()
	start := strings.Index(guide, "\n"+heading)
	if start < 0 {
		t.Fatalf("guide has no %q heading", heading)
	}
	section := guide[start+1:]
	level := strings.Index(heading, " ")
	if end := regexp.MustCompile("\n#{1," + strconv.Itoa(level) + "} ").FindStringIndex(section[len(heading):]); end != nil {
		section = section[:len(heading)+end[0]]
	}
	return section
}

// walkSources hands every non-test source file under the given roots to fn
// as (repo-relative path, body).
func walkSources(t *testing.T, roots []string, suffixes []string, fn func(path, body string)) {
	t.Helper()
	for _, root := range roots {
		err := filepath.WalkDir(filepath.Join("..", "..", root), func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			ok := false
			for _, suffix := range suffixes {
				ok = ok || strings.HasSuffix(path, suffix)
			}
			if !ok {
				return nil
			}
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			fn(filepath.ToSlash(strings.TrimPrefix(path, filepath.Join("..", "..")+string(filepath.Separator))), string(body))
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}

// The "막혔을 때" table in the user guide quotes the messages people actually
// see, so that someone can search the guide for the text on their screen.
// A message that is reworded in the server or the screen without the guide
// following leaves that search empty-handed. Every quoted phrase has to exist
// letter for letter somewhere the user can be shown it: a server message
// literal or a string in the web sources. What the message fills in at
// runtime is written as `N` before a counter (`N분 후`, `미검토 항목 N건`) or
// as `<…>` (`허용되지 않은 확장자입니다: <확장자>`), so the phrase is checked
// around those.
func TestUserGuideErrorMessagesAreTheOnesTheScreenShows(t *testing.T) {
	section := guideSection(t, repoFile(t, filepath.Join("docs", "USER_GUIDE.md")), "## 5. 막혔을 때")
	var corpus strings.Builder
	walkSources(t, []string{"internal", "cmd", filepath.Join("web", "src")}, []string{".go", ".ts", ".tsx"}, func(_, body string) {
		corpus.WriteString(body)
		corpus.WriteByte('\n')
	})
	sources := corpus.String()

	quoted := regexp.MustCompile("`([^`]+)`")
	placeholder := regexp.MustCompile("N([분건개회일])|<[^>]+>")
	rows := 0
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| :---") || strings.HasPrefix(line, "| 화면에 보이는 메시지") {
			continue
		}
		rows++
		cell := strings.TrimSpace(strings.SplitN(line[2:], " | ", 2)[0])
		phrases := quoted.FindAllStringSubmatch(cell, -1)
		if len(phrases) == 0 {
			t.Errorf("the row %q quotes no message in backticks; the table is for text the user can search for", cell)
			continue
		}
		for _, m := range phrases {
			for _, fragment := range strings.Split(placeholder.ReplaceAllString(m[1], "\x00$1"), "\x00") {
				fragment = strings.TrimSpace(fragment)
				if len([]rune(fragment)) < 2 {
					continue
				}
				if !strings.Contains(sources, fragment) {
					t.Errorf("the user guide quotes %q and nothing in the server or the screen says it", m[1])
					break
				}
			}
		}
	}
	if rows < 10 {
		t.Fatalf("parsed only %d rows from the 막혔을 때 table; its shape must have changed", rows)
	}
}

// storeLogCalls returns every (component, message) pair the code writes to
// the 서버 로그 screen through Store.Log, plus the set of components alone.
func storeLogCalls(t *testing.T) (map[string]map[string]bool, map[string]bool) {
	t.Helper()
	call := regexp.MustCompile(`\.Log\([^,]+,\s*"[A-Z]+",\s*[^,]+,\s*"([a-z_]+)",\s*("([^"]+)"|[a-zA-Z.]+)`)
	messages := map[string]map[string]bool{}
	components := map[string]bool{}
	walkSources(t, []string{"internal", "cmd"}, []string{".go"}, func(_, body string) {
		for _, m := range call.FindAllStringSubmatch(body, -1) {
			components[m[1]] = true
			if m[3] != "" {
				if messages[m[1]] == nil {
					messages[m[1]] = map[string]bool{}
				}
				messages[m[1]][m[3]] = true
			}
		}
	})
	if len(components) < 5 {
		t.Fatalf("only %d log components found in the code; the Store.Log call shape must have changed", len(components))
	}
	return messages, components
}

// The admin guide's 장애 대응 table tells an operator which line to look for.
// A line is quoted in one of two places and the test holds each to its
// source: "로그에 `…`" is a startup failure that only ever reaches the
// container's standard output, so it must be a string literal somewhere in
// the Go code; "서버 로그 `component` 의 `…`" is a row on the 서버 로그 screen,
// so the code must call Store.Log with exactly that component and message --
// a message the process prints to stderr instead would never appear there.
// The table had quoted such a stderr line under a screen component when this
// was written. The component list in 5-3 is held to the code the same way.
func TestAdminGuideLogPhrasesAreTheOnesTheServerWrites(t *testing.T) {
	guide := repoFile(t, filepath.Join("docs", "ADMIN_GUIDE.md"))
	messages, components := storeLogCalls(t)

	listed := guideSection(t, guide, "### 5-3. 로그")
	m := regexp.MustCompile("`component`\\(((?:`[a-z_]+`(?:, )?)+)\\)").FindStringSubmatch(listed)
	if m == nil {
		t.Fatal("5-3 no longer lists the log components after `component`")
	}
	documented := map[string]bool{}
	for _, name := range regexp.MustCompile("`([a-z_]+)`").FindAllStringSubmatch(m[1], -1) {
		documented[name[1]] = true
	}
	for name := range components {
		if !documented[name] {
			t.Errorf("the code writes 서버 로그 rows with component %q and 5-3 does not list it", name)
		}
	}
	for name := range documented {
		if !components[name] {
			t.Errorf("5-3 lists the log component %q and nothing in the code writes it", name)
		}
	}

	var goSources strings.Builder
	walkSources(t, []string{"internal", "cmd"}, []string{".go"}, func(_, body string) {
		goSources.WriteString(body)
		goSources.WriteByte('\n')
	})
	table := guideSection(t, guide, "## 6. 장애 대응")
	stdout := regexp.MustCompile("로그에 `([^`]+)`(?: 또는 `([^`]+)`)?")
	screen := regexp.MustCompile("서버 로그 `([a-z_]+)` (?:의 ((?:`[^`]+`(?: / )?)+)|\\(((?:`[^`]+`(?:, )?)+) 등\\))")
	quoted := regexp.MustCompile("`([^`]+)`")
	seen := 0
	for _, line := range strings.Split(table, "\n") {
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| :---") || strings.HasPrefix(line, "| 증상") {
			continue
		}
		for _, m := range stdout.FindAllStringSubmatch(line, -1) {
			for _, phrase := range m[1:] {
				if phrase == "" {
					continue
				}
				seen++
				if !strings.Contains(goSources.String(), phrase) {
					t.Errorf("the admin guide says the log shows %q and nothing in the code prints it", phrase)
				}
			}
		}
		for _, m := range screen.FindAllStringSubmatch(line, -1) {
			component := m[1]
			for _, q := range quoted.FindAllStringSubmatch(m[2]+m[3], -1) {
				seen++
				if !messages[component][q[1]] {
					t.Errorf("the admin guide says 서버 로그 component %q shows %q and no Store.Log call writes that pair", component, q[1])
				}
			}
		}
	}
	if seen < 10 {
		t.Fatalf("recognised only %d quoted log lines in the 장애 대응 table; its wording must have changed", seen)
	}
}
