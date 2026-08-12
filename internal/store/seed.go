package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/xuri/excelize/v2"
)

type seedSheet struct {
	Sheet, Name, Category, Version                                              string
	HeaderRow                                                                   int
	SectionCols                                                                 []int
	CodeCol, TitleCol, QuestionCol, GuideCol, LegalCol, ExampleCol, SeverityCol int
}

var defaultSeedSheets = []seedSheet{
	{Sheet: "개발보안 체크리스트 V2.5", Name: "개발보안", Category: "DEVELOPMENT", Version: "V2.5", HeaderRow: 7, SectionCols: []int{1}, CodeCol: 2, TitleCol: 3, QuestionCol: 4, GuideCol: -1, LegalCol: -1, ExampleCol: 6, SeverityCol: -1},
	{Sheet: "개인(신용)정보 체크리스트 V1.0", Name: "개인(신용)정보", Category: "PRIVACY", Version: "V1.0", HeaderRow: 10, SectionCols: []int{1}, CodeCol: 2, TitleCol: 3, QuestionCol: 3, GuideCol: 4, LegalCol: 5, ExampleCol: 7, SeverityCol: -1},
	{Sheet: "클라우드 서비스 체크리스트 V1.0", Name: "클라우드 서비스", Category: "CLOUD", Version: "V1.0", HeaderRow: 7, SectionCols: []int{0}, CodeCol: -1, TitleCol: 1, QuestionCol: 1, GuideCol: 2, LegalCol: -1, ExampleCol: 4, SeverityCol: -1},
	{Sheet: "(참고)컨테이너보안설정(Docker)", Name: "Docker 보안", Category: "DOCKER", Version: "V1.0", HeaderRow: 3, SectionCols: []int{1}, CodeCol: 2, TitleCol: 4, QuestionCol: 5, GuideCol: 6, LegalCol: -1, ExampleCol: 7, SeverityCol: 3},
	{Sheet: "(참고)컨테이너보안설정(Kubernetes)", Name: "Kubernetes 보안", Category: "KUBERNETES", Version: "V1.0", HeaderRow: 3, SectionCols: []int{1, 2}, CodeCol: 3, TitleCol: 5, QuestionCol: 6, GuideCol: 7, LegalCol: -1, ExampleCol: 8, SeverityCol: 4},
}

type seedItem struct {
	Section, Code, Title, Question, Guide, Legal, Example, Severity string
	Order                                                           int
}

type DefaultChecklist struct {
	Name     string                 `json:"name"`
	Category string                 `json:"category"`
	Version  string                 `json:"version"`
	Items    []DefaultChecklistItem `json:"items"`
}

type DefaultChecklistItem struct {
	Section  string `json:"section"`
	Code     string `json:"code"`
	Title    string `json:"title"`
	Question string `json:"question"`
	Guide    string `json:"guide"`
	Legal    string `json:"legal"`
	Example  string `json:"example"`
	Severity string `json:"severity"`
	Order    int    `json:"order"`
}

//go:embed default_checklists.json
var embeddedDefaultChecklists []byte

// ExtractWorkbookDefaults converts the provided source workbook into the
// source-independent representation embedded by production builds.
func ExtractWorkbookDefaults(path string) ([]DefaultChecklist, error) {
	f, err := excelize.OpenFile(path)
	if err != nil {
		return nil, fmt.Errorf("open baseline workbook: %w", err)
	}
	defer f.Close()
	checklists := make([]DefaultChecklist, 0, len(defaultSeedSheets))
	for _, spec := range defaultSeedSheets {
		rows, err := f.GetRows(spec.Sheet)
		if err != nil {
			return nil, fmt.Errorf("read seed sheet %q: %w", spec.Sheet, err)
		}
		parsed := seedItems(rows, spec)
		if len(parsed) == 0 {
			return nil, fmt.Errorf("seed sheet %q has no checklist items", spec.Sheet)
		}
		items := make([]DefaultChecklistItem, 0, len(parsed))
		for _, item := range parsed {
			items = append(items, DefaultChecklistItem(item))
		}
		checklists = append(checklists, DefaultChecklist{Name: spec.Name, Category: spec.Category, Version: spec.Version, Items: items})
	}
	return checklists, nil
}

// SeedDefaults publishes the normalized baseline only on a completely fresh
// installation. Later changes always go through versioned administration APIs.
func (s *Store) SeedDefaults(ctx context.Context, creatorID string) (int, error) {
	var existing int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM checklist_templates`).Scan(&existing); err != nil {
		return 0, err
	}
	if existing > 0 {
		return 0, nil
	}
	var checklists []DefaultChecklist
	if err := json.Unmarshal(embeddedDefaultChecklists, &checklists); err != nil {
		return 0, fmt.Errorf("decode embedded default checklists: %w", err)
	}
	if len(checklists) == 0 {
		return 0, fmt.Errorf("embedded default checklists are empty")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	total := 0
	for _, checklist := range checklists {
		if len(checklist.Items) == 0 {
			return 0, fmt.Errorf("embedded checklist %q has no items", checklist.Name)
		}
		tid, vid := NewID(), NewID()
		if _, err = tx.Exec(ctx, `INSERT INTO checklist_templates(id,name,category,description,created_by) VALUES($1,$2,$3,$4,$5)`, tid, checklist.Name, checklist.Category, "SecCheck 기본 체크리스트", creatorID); err != nil {
			return 0, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO checklist_versions(id,template_id,version,status,change_note,source_filename,created_by,published_by,published_at) VALUES($1,$2,$3,'PUBLISHED','기본 체크리스트 자동 등록','SecCheck embedded defaults',$4,$4,now())`, vid, tid, checklist.Version, creatorID); err != nil {
			return 0, err
		}
		sections := map[string]string{}
		for _, item := range checklist.Items {
			secID := sections[item.Section]
			if secID == "" && item.Section != "" {
				secID = NewID()
				sections[item.Section] = secID
				if _, err = tx.Exec(ctx, `INSERT INTO checklist_sections(id,version_id,name,sort_order) VALUES($1,$2,$3,$4)`, secID, vid, item.Section, len(sections)); err != nil {
					return 0, err
				}
			}
			if _, err = tx.Exec(ctx, `INSERT INTO checklist_items(id,version_id,section_id,item_code,category,title,question,guide,legal_basis,example,severity,required,answer_type,evidence_required,sort_order) VALUES($1,$2,NULLIF($3,''),$4,$5,$6,$7,$8,$9,$10,$11,true,'YNNA',false,$12)`, NewID(), vid, secID, item.Code, checklist.Category, item.Title, item.Question, item.Guide, item.Legal, item.Example, item.Severity, item.Order); err != nil {
				return 0, err
			}
			total++
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return total, nil
}

func seedItems(rows [][]string, spec seedSheet) []seedItem {
	items := []seedItem{}
	lastSections := make([]string, len(spec.SectionCols))
	seen := map[string]int{}
	cell := func(row []string, col int) string {
		if col < 0 || col >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[col])
	}
	for i := spec.HeaderRow + 1; i < len(rows); i++ {
		row := rows[i]
		sections := []string{}
		for n, col := range spec.SectionCols {
			if v := cell(row, col); v != "" {
				lastSections[n] = v
			}
			if lastSections[n] != "" {
				sections = append(sections, lastSections[n])
			}
		}
		title, question := cell(row, spec.TitleCol), cell(row, spec.QuestionCol)
		if title == "" && question != "" {
			title = seedTruncate(question, 80)
		}
		if question == "" {
			question = title
		}
		if title == "" {
			continue
		}
		code := normalizeSeedCode(cell(row, spec.CodeCol))
		if code == "" {
			code = fmt.Sprintf("%s-%03d", spec.Category, i-spec.HeaderRow)
		}
		seen[code]++
		if seen[code] > 1 {
			code = fmt.Sprintf("%s-DUP%d", code, seen[code])
		}
		items = append(items, seedItem{Section: strings.Join(sections, " / "), Code: code, Title: title, Question: question, Guide: cell(row, spec.GuideCol), Legal: cell(row, spec.LegalCol), Example: cell(row, spec.ExampleCol), Severity: seedSeverity(cell(row, spec.SeverityCol)), Order: i - spec.HeaderRow})
	}
	return items
}

func normalizeSeedCode(code string) string {
	if len(code) > 10 && strings.Contains(code, ".") {
		if n, err := strconv.ParseFloat(code, 64); err == nil {
			return strconv.FormatFloat(n, 'f', -1, 64)
		}
	}
	return code
}
func seedSeverity(v string) string {
	switch strings.ToUpper(v) {
	case "상", "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "하", "LOW":
		return "LOW"
	default:
		return "MEDIUM"
	}
}
func seedTruncate(v string, n int) string {
	r := []rune(v)
	if len(r) <= n {
		return v
	}
	return string(r[:n]) + "…"
}
