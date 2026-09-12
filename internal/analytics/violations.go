package analytics

import (
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// MaxViolations bounds the recorder. A blocked request repeats on every page
// view, so what matters is which origins are blocked, not how many times --
// a short list of distinct origins is enough to fix a snippet.
const MaxViolations = 100

// Violation is one origin the content security policy refused, kept with the
// directive that refused it so the screen can say what to allow.
type Violation struct {
	Origin    string    `json:"origin"`
	Directive string    `json:"directive"`
	Page      string    `json:"page"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Allowed marks an origin the current settings already let through, so a
	// fixed snippet stops nagging without anyone clearing the list.
	Allowed bool `json:"allowed"`
}

// Recorder collects the policy violations browsers report. It is deliberately
// in memory: the reports are a live troubleshooting aid for the person
// pasting a snippet, not an audit record, and keeping them out of the
// database means the browser can report freely without growing storage.
type Recorder struct {
	mu         sync.Mutex
	violations map[string]*Violation
	now        func() time.Time
}

func NewRecorder() *Recorder {
	return &Recorder{violations: map[string]*Violation{}, now: time.Now}
}

// Record notes one blocked request. Anything that is not an http origin --
// a browser extension, a data: URL, the "inline" and "eval" keywords -- is
// dropped because allowing it is neither possible nor useful.
func (r *Recorder) Record(blockedURI, directive, page string) {
	origin := originOf(blockedURI)
	if origin == "" {
		return
	}
	directive = strings.TrimSpace(strings.ToLower(directive))
	if i := strings.IndexByte(directive, ' '); i > 0 {
		directive = directive[:i]
	}
	if directive == "" {
		directive = "connect-src"
	}
	if u, err := url.Parse(page); err == nil && u.Path != "" {
		page = u.Path // the page is kept for orientation only; never its query
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := directive + " " + origin
	if v, found := r.violations[key]; found {
		v.Count++
		v.LastSeen = r.now()
		v.Page = page
		return
	}
	if len(r.violations) >= MaxViolations {
		r.evictOldest()
	}
	at := r.now()
	r.violations[key] = &Violation{Origin: origin, Directive: directive, Page: page, Count: 1, FirstSeen: at, LastSeen: at}
}

func (r *Recorder) evictOldest() {
	var oldestKey string
	var oldest time.Time
	for key, v := range r.violations {
		if oldestKey == "" || v.LastSeen.Before(oldest) {
			oldestKey, oldest = key, v.LastSeen
		}
	}
	delete(r.violations, oldestKey)
}

// List returns the blocked origins, most recent first, marking the ones the
// given configuration already allows.
func (r *Recorder) List(config Config) []Violation {
	allowed := map[string]bool{}
	scripts, connects, images := config.PolicySources()
	for _, group := range [][]string{scripts, connects, images} {
		for _, origin := range group {
			allowed[strings.ToLower(strings.TrimSuffix(origin, "/"))] = true
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	items := make([]Violation, 0, len(r.violations))
	for _, v := range r.violations {
		item := *v
		item.Allowed = allowed[strings.ToLower(item.Origin)] || matchesWildcard(item.Origin, allowed)
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeen.Equal(items[j].LastSeen) {
			return items[i].Origin < items[j].Origin
		}
		return items[i].LastSeen.After(items[j].LastSeen)
	})
	return items
}

// Forget drops the recorded violations, which is what an administrator does
// after fixing a snippet to see whether anything is still blocked.
func (r *Recorder) Forget() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.violations = map[string]*Violation{}
}

// matchesWildcard covers policy entries such as https://*.google-analytics.com.
func matchesWildcard(origin string, allowed map[string]bool) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	lower := strings.ToLower(origin)
	for pattern := range allowed {
		star := strings.Index(pattern, "*.")
		if star < 0 {
			continue
		}
		if strings.HasPrefix(lower, pattern[:star]) && strings.HasSuffix(strings.ToLower(parsed.Host), pattern[star+1:]) {
			return true
		}
	}
	return false
}
