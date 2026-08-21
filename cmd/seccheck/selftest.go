package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"
)

// The upgrade procedure in the operations guide asks for a new image to be
// started in a separate environment and checked -- readiness, sign-in, the
// snapshot, an evidence download. That was prose, so it was done by hand or
// not at all. This runs the same checks and answers with an exit status.
//
// Read-only by default. --full additionally creates a review, which exercises
// the rule engine and the three export formats; the PDF in particular can
// only be produced where the Korean font is installed, so it is not something
// the test suite can prove about a built image.

type selftestClient struct {
	base string
	http *http.Client
	csrf string
}

type selftestStep struct {
	name string
	err  error
	note string
}

func runSelftest(args []string) int {
	base := "http://127.0.0.1:8080"
	username, password := "", ""
	full, asJSON := false, false
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
		if v, ok := value("--base-url"); ok {
			base = strings.TrimRight(v, "/")
			continue
		}
		if v, ok := value("--username"); ok {
			username = v
			continue
		}
		if v, ok := value("--password"); ok {
			password = v
			continue
		}
		switch args[i] {
		case "--full":
			full = true
		case "--json":
			asJSON = true
		default:
			fmt.Fprintf(os.Stderr, "unknown argument %q; expected --base-url, --username, --password, --full or --json\n", args[i])
			return 2
		}
	}
	if password == "" {
		password = os.Getenv("SECCHECK_SELFTEST_PASSWORD")
	}
	if username == "" || password == "" {
		fmt.Fprintln(os.Stderr, "--username and --password (or SECCHECK_SELFTEST_PASSWORD) are required")
		return 2
	}

	jar, _ := cookiejar.New(nil)
	c := &selftestClient{base: base, http: &http.Client{Timeout: 60 * time.Second, Jar: jar}}
	steps := c.run(username, password, full)

	failed := 0
	for _, step := range steps {
		if step.err != nil {
			failed++
		}
	}
	if asJSON {
		out := make([]map[string]any, 0, len(steps))
		for _, step := range steps {
			entry := map[string]any{"step": step.name, "ok": step.err == nil, "detail": step.note}
			if step.err != nil {
				entry["error"] = step.err.Error()
			}
			out = append(out, entry)
		}
		body, _ := json.MarshalIndent(map[string]any{"base_url": base, "failed": failed, "steps": out}, "", "  ")
		fmt.Println(string(body))
	} else {
		for _, step := range steps {
			if step.err != nil {
				fmt.Printf("FAIL  %-22s %v\n", step.name, step.err)
				continue
			}
			fmt.Printf("ok    %-22s %s\n", step.name, step.note)
		}
		fmt.Printf("\n%d/%d checks passed against %s\n", len(steps)-failed, len(steps), base)
	}
	if failed > 0 {
		return 1
	}
	return 0
}

func (c *selftestClient) run(username, password string, full bool) []selftestStep {
	steps := []selftestStep{}
	record := func(name string, note string, err error) bool {
		steps = append(steps, selftestStep{name: name, note: note, err: err})
		return err == nil
	}

	if !record("health", "프로세스 생존", c.expect("GET", "/health", nil, nil)) {
		return steps
	}
	record("ready", "DB 연결 포함 준비 상태", c.expect("GET", "/ready", nil, nil))

	var login struct {
		CSRF string `json:"csrf_token"`
		User struct {
			ID    string   `json:"id"`
			Roles []string `json:"roles"`
		} `json:"user"`
	}
	if !record("sign-in", username, c.expect("POST", "/api/v1/auth/login", map[string]any{"username": username, "password": password}, &login)) {
		return steps
	}
	c.csrf = login.CSRF

	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	record("openapi", "", c.expect("GET", "/api/openapi.json", nil, &spec))
	steps[len(steps)-1].note = fmt.Sprintf("%d개 경로", len(spec.Paths))

	var templates struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if record("templates", "", c.expect("GET", "/api/v1/templates?limit=100", nil, &templates)) {
		steps[len(steps)-1].note = fmt.Sprintf("%d개 템플릿", len(templates.Items))
		if len(templates.Items) == 0 {
			steps[len(steps)-1].err = fmt.Errorf("게시된 템플릿이 없어 심의를 만들 수 없습니다")
		}
	}

	var chain struct {
		Valid   bool  `json:"valid"`
		Checked int64 `json:"checked"`
	}
	if record("audit-chain", "", c.expect("GET", "/api/v1/admin/audit/verify", nil, &chain)) {
		steps[len(steps)-1].note = fmt.Sprintf("%d건 검증", chain.Checked)
		if !chain.Valid {
			steps[len(steps)-1].err = fmt.Errorf("감사로그 해시 체인 검증에 실패했습니다")
		}
	}

	if !full {
		steps = append(steps, selftestStep{name: "review-flow", note: "건너뜀 (--full 로 실행)"})
		return steps
	}

	var created struct {
		ID string `json:"id"`
	}
	review := map[string]any{
		"service_name": "자체 점검 " + time.Now().Format("2006-01-02 15:04"), "description": "seccheck selftest",
		"service_type": "WEB", "change_type": "NEW", "builder_id": login.User.ID, "developer_id": login.User.ID,
		"department": "selftest", "exposure": "INTERNAL", "internet_access": true,
	}
	if !record("review-create", "", c.expect("POST", "/api/v1/review-requests", review, &created)) {
		return steps
	}
	var detail struct {
		ReviewNumber string         `json:"review_number"`
		Progress     map[string]int `json:"progress"`
	}
	if record("review-detail", "", c.expect("GET", "/api/v1/review-requests/"+created.ID, nil, &detail)) {
		steps[len(steps)-1].note = fmt.Sprintf("%s · 항목 %d개 배정", detail.ReviewNumber, detail.Progress["total"])
		if detail.Progress["total"] == 0 {
			steps[len(steps)-1].err = fmt.Errorf("Rule Engine이 항목을 하나도 배정하지 않았습니다")
		}
	}
	// The PDF needs the Korean font installed in the image, which is the one
	// thing the test suite cannot prove about a build.
	for _, format := range []string{"xlsx", "pdf", "zip"} {
		size, err := c.download("/api/v1/review-requests/" + created.ID + "/export/" + format)
		record("export-"+format, fmt.Sprintf("%d bytes", size), err)
	}
	return steps
}

func (c *selftestClient) expect(method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("%s %s → %d %s", method, path, res.StatusCode, strings.TrimSpace(string(payload[:min(len(payload), 200)])))
	}
	if out != nil {
		if err := json.Unmarshal(payload, out); err != nil {
			return fmt.Errorf("%s %s → 응답을 해석하지 못했습니다: %w", method, path, err)
		}
	}
	return nil
}

func (c *selftestClient) download(path string) (int64, error) {
	req, err := http.NewRequest("GET", c.base+path, nil)
	if err != nil {
		return 0, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(io.LimitReader(res.Body, 4<<10))
		return 0, fmt.Errorf("GET %s → %d %s", path, res.StatusCode, strings.TrimSpace(string(payload)))
	}
	size, err := io.Copy(io.Discard, res.Body)
	if err != nil {
		return size, fmt.Errorf("전송이 중간에 끊겼습니다: %w", err)
	}
	if size == 0 {
		return 0, fmt.Errorf("빈 파일이 반환되었습니다")
	}
	return size, nil
}
