package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/xuri/excelize/v2"
)

// The security team reports to management on a period, not on "everything ever
// recorded". The dashboard only ever showed all-time counts for the whole
// installation and had no export, so those numbers were assembled by hand.

type reportScope struct {
	where string
	args  []any
	from  string
	to    string
	// includeDone keeps carried-out actions in the register. They are hidden
	// by default because the register is a list of what is still owed.
	includeDone bool
}

// reportFilter bounds the report by creation date and optionally by
// department. Dates are half-open on the upper bound so a whole day counts.
func reportFilter(r *http.Request) reportScope {
	scope := reportScope{where: "TRUE"}
	query := r.URL.Query()
	if from := strings.TrimSpace(query.Get("from")); from != "" {
		scope.args = append(scope.args, from)
		scope.where += fmt.Sprintf(" AND r.created_at >= display_day_start($%d::date)", len(scope.args))
		scope.from = from
	}
	if to := strings.TrimSpace(query.Get("to")); to != "" {
		scope.args = append(scope.args, to)
		scope.where += fmt.Sprintf(" AND r.created_at < display_day_start($%d::date + 1)", len(scope.args))
		scope.to = to
	}
	scope.includeDone = query.Get("include_done") == "1"
	if department := strings.TrimSpace(query.Get("department")); department != "" {
		scope.args = append(scope.args, department)
		scope.where += fmt.Sprintf(" AND r.department = $%d", len(scope.args))
	}
	return scope
}

type reportData struct {
	From         string           `json:"from"`
	To           string           `json:"to"`
	Totals       map[string]any   `json:"totals"`
	CycleTime    map[string]any   `json:"cycle_time"`
	ByStatus     []map[string]any `json:"by_status"`
	ByDepartment []map[string]any `json:"by_department"`
	ByResult     []map[string]any `json:"by_result"`
	Recurring    []map[string]any `json:"recurring_findings"`
	FollowUps    []map[string]any `json:"follow_ups"`
	Aging        []map[string]any `json:"aging"`
}

func (s *Server) reviewReport(w http.ResponseWriter, r *http.Request) {
	scope := reportFilter(r)
	data, err := s.buildReport(r, scope)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "리포트를 만들지 못했습니다.", err)
		return
	}
	if r.URL.Query().Get("format") == "xlsx" {
		_ = s.Store.Audit(r.Context(), auditFrom(r, "EXPORT_REPORT", "REVIEW_REQUEST", "", nil, map[string]any{"from": scope.from, "to": scope.to}))
		s.writeReportWorkbook(w, r, data)
		return
	}
	jsonResponse(w, 200, data)
}

func (s *Server) buildReport(r *http.Request, scope reportScope) (reportData, error) {
	ctx := r.Context()
	data := reportData{From: scope.from, To: scope.to, Totals: map[string]any{}, CycleTime: map[string]any{}}

	var created, submitted, completed, rejected, open int64
	err := s.Store.Pool.QueryRow(ctx, `SELECT count(*),
                count(*) FILTER (WHERE r.first_submitted_at IS NOT NULL),
                count(*) FILTER (WHERE r.status IN ('APPROVED','CLOSED')),
                count(*) FILTER (WHERE r.status='REJECTED'),
                count(*) FILTER (WHERE r.status NOT IN ('APPROVED','CLOSED','REJECTED','CANCELLED'))
                FROM review_requests r WHERE `+scope.where, scope.args...).
		Scan(&created, &submitted, &completed, &rejected, &open)
	if err != nil {
		return data, err
	}
	data.Totals = map[string]any{"created": created, "submitted": submitted, "completed": completed, "rejected": rejected, "in_progress": open}

	// Cycle time measures first submission to approval, which is the number a
	// requester actually experiences.
	var avg, p50, p90 *float64
	var measured int64
	err = s.Store.Pool.QueryRow(ctx, `SELECT count(*),
                avg(EXTRACT(EPOCH FROM (r.approved_at - r.first_submitted_at))/86400),
                percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (r.approved_at - r.first_submitted_at))/86400),
                percentile_cont(0.9) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (r.approved_at - r.first_submitted_at))/86400)
                FROM review_requests r WHERE `+scope.where+` AND r.approved_at IS NOT NULL AND r.first_submitted_at IS NOT NULL`, scope.args...).
		Scan(&measured, &avg, &p50, &p90)
	if err != nil {
		return data, err
	}
	data.CycleTime = map[string]any{"measured": measured, "average_days": round1(avg), "median_days": round1(p50), "p90_days": round1(p90)}

	if data.ByStatus, err = s.reportRows(ctx, `SELECT r.status,count(*) FROM review_requests r WHERE `+scope.where+` GROUP BY r.status ORDER BY count(*) DESC`, scope.args, "status", "count"); err != nil {
		return data, err
	}
	if data.ByDepartment, err = s.reportRows(ctx, `SELECT r.department,count(*),
                count(*) FILTER (WHERE r.status IN ('APPROVED','CLOSED')),
                COALESCE(round(avg(EXTRACT(EPOCH FROM (r.approved_at - r.first_submitted_at))/86400)::numeric,1),0)
                FROM review_requests r WHERE `+scope.where+` GROUP BY r.department ORDER BY count(*) DESC LIMIT 50`,
		scope.args, "department", "created", "completed", "average_days"); err != nil {
		return data, err
	}
	if data.ByResult, err = s.reportRows(ctx, `SELECT rr.result,count(*) FROM review_results rr
                JOIN submission_items si ON si.id=rr.submission_item_id
                JOIN submissions sub ON sub.id=si.submission_id
                JOIN review_requests r ON r.id=sub.review_request_id
                WHERE `+scope.where+` AND rr.result<>'' GROUP BY rr.result ORDER BY count(*) DESC`, scope.args, "result", "count"); err != nil {
		return data, err
	}
	if data.Recurring, err = s.reportRows(ctx, `SELECT si.item_code,si.title,si.category,count(*) FROM review_results rr
                JOIN submission_items si ON si.id=rr.submission_item_id
                JOIN submissions sub ON sub.id=si.submission_id
                JOIN review_requests r ON r.id=sub.review_request_id
                WHERE `+scope.where+` AND rr.result IN ('INSUFFICIENT','NON_COMPLIANT')
                GROUP BY si.item_code,si.title,si.category ORDER BY count(*) DESC,si.item_code LIMIT 20`,
		scope.args, "item_code", "title", "category", "count"); err != nil {
		return data, err
	}
	// A conditional pass usually comes with something the team promised to do
	// later, written on the item and then visible only inside the one review
	// that produced it. Collected here, they are the commitments outstanding
	// across everything -- which is the work that follows a review.
	// Outstanding actions come first, because they are the ones still owed.
	// Completed entries stay visible: what was promised and closed is as much
	// a part of the record as what is open.
	done := ""
	if !scope.includeDone {
		done = " AND rr.follow_up_done_at IS NULL"
	}
	if data.FollowUps, err = s.reportRows(ctx, `SELECT rr.id,r.review_number,r.service_name,r.department,si.item_code,si.title,rr.result,rr.follow_up,
                to_char(display_date(COALESCE(r.approved_at,r.updated_at)),'YYYY-MM-DD') AS decided_on,
                to_char(rr.follow_up_due_date,'YYYY-MM-DD') AS due_on,
                (rr.follow_up_done_at IS NULL AND rr.follow_up_due_date IS NOT NULL AND rr.follow_up_due_date < display_today()) AS overdue,
                to_char(display_date(rr.follow_up_reported_at),'YYYY-MM-DD') AS reported_on,
                COALESCE(ru.display_name,'') AS reported_by,
                to_char(display_date(rr.follow_up_done_at),'YYYY-MM-DD') AS done_on,
                COALESCE(u.display_name,'') AS done_by, rr.follow_up_note
                FROM review_results rr
                JOIN submission_items si ON si.id=rr.submission_item_id
                JOIN submissions sub ON sub.id=si.submission_id
                JOIN review_requests r ON r.id=sub.review_request_id
                LEFT JOIN users u ON u.id=rr.follow_up_done_by
                LEFT JOIN users ru ON ru.id=rr.follow_up_reported_by
                WHERE `+scope.where+` AND btrim(rr.follow_up)<>''`+done+`
                ORDER BY rr.follow_up_done_at NULLS FIRST,rr.follow_up_due_date NULLS LAST,COALESCE(r.approved_at,r.updated_at) DESC,r.review_number,si.item_code LIMIT 500`,
		scope.args, "id", "review_number", "service_name", "department", "item_code", "title", "result", "follow_up", "decided_on", "due_on", "overdue", "reported_on", "reported_by", "done_on", "done_by", "follow_up_note"); err != nil {
		return data, err
	}
	// Aging looks at what is still open right now, which is the queue the team
	// has to work down rather than a property of the period.
	if data.Aging, err = s.reportRows(ctx, `SELECT bucket,count(*) FROM (
                  SELECT CASE
                    WHEN now()-r.updated_at < interval '3 days' THEN '3일 미만'
                    WHEN now()-r.updated_at < interval '7 days' THEN '3~7일'
                    WHEN now()-r.updated_at < interval '14 days' THEN '7~14일'
                    ELSE '14일 이상' END AS bucket
                  FROM review_requests r WHERE `+scope.where+` AND r.status NOT IN ('APPROVED','CLOSED','REJECTED','CANCELLED')) aged
                GROUP BY bucket ORDER BY min(CASE bucket WHEN '3일 미만' THEN 1 WHEN '3~7일' THEN 2 WHEN '7~14일' THEN 3 ELSE 4 END)`,
		scope.args, "bucket", "count"); err != nil {
		return data, err
	}
	return data, nil
}

func (s *Server) reportRows(ctx context.Context, query string, args []any, columns ...string) ([]map[string]any, error) {
	rows, err := s.Store.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return scanDynamic(rows, columns)
}

func round1(v *float64) float64 {
	if v == nil {
		return 0
	}
	return float64(int(*v*10+0.5)) / 10
}

// writeReportWorkbook lays the same numbers out as a workbook, because that is
// what gets attached to a monthly report.
func (s *Server) writeReportWorkbook(w http.ResponseWriter, r *http.Request, data reportData) {
	f := excelize.NewFile()
	defer f.Close()
	period := valueDefault(data.From, "전체") + " ~ " + valueDefault(data.To, "전체")

	summary := "요약"
	f.SetSheetName("Sheet1", summary)
	rowsOf := [][]any{
		{"SecCheck 보안성 심의 리포트"},
		{"대상 기간", period},
		{"생성 시각", s.exportedAt()},
		{},
		{"신규 심의", data.Totals["created"]},
		{"제출된 심의", data.Totals["submitted"]},
		{"완료(승인·종료)", data.Totals["completed"]},
		{"반려", data.Totals["rejected"]},
		{"진행 중", data.Totals["in_progress"]},
		{},
		{"처리 기간 (제출→승인)", ""},
		{"측정 건수", data.CycleTime["measured"]},
		{"평균 일수", data.CycleTime["average_days"]},
		{"중앙값 일수", data.CycleTime["median_days"]},
		{"90분위 일수", data.CycleTime["p90_days"]},
	}
	writeSheetRows(f, summary, rowsOf, 1)

	sheets := []struct {
		name    string
		header  []any
		columns []string
		rows    []map[string]any
	}{
		{"상태별", []any{"상태", "건수"}, []string{"status", "count"}, data.ByStatus},
		{"부서별", []any{"부서", "신규", "완료", "평균 처리일"}, []string{"department", "created", "completed", "average_days"}, data.ByDepartment},
		{"검토 결과", []any{"판정", "항목 수"}, []string{"result", "count"}, data.ByResult},
		{"반복 미흡 항목", []any{"항목코드", "보안요건", "분류", "발생 건수"}, []string{"item_code", "title", "category", "count"}, data.Recurring},
		{"경과 기간", []any{"경과", "진행 중 건수"}, []string{"bucket", "count"}, data.Aging},
		{"미조치 항목", []any{"심의번호", "서비스", "부서", "항목코드", "보안요건", "판정", "조치 사항", "판정일", "조치 기한", "기한 초과", "보고일", "보고자", "확인일", "확인자", "이행 결과"},
			[]string{"review_number", "service_name", "department", "item_code", "title", "result", "follow_up", "decided_on", "due_on", "overdue", "reported_on", "reported_by", "done_on", "done_by", "follow_up_note"}, data.FollowUps},
	}
	for _, sheet := range sheets {
		if _, err := f.NewSheet(sheet.name); err != nil {
			continue
		}
		body := [][]any{sheet.header}
		for _, record := range sheet.rows {
			row := make([]any, 0, len(sheet.columns))
			for _, column := range sheet.columns {
				row = append(row, record[column])
			}
			body = append(body, row)
		}
		writeSheetRows(f, sheet.name, body, 1)
	}

	name := sanitizeFilename("seccheck-report-" + valueDefault(data.From, "all") + "-" + valueDefault(data.To, "all"))
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", `attachment; filename*=UTF-8''`+urlEncode(name+".xlsx"))
	_ = f.Write(w)
}

func writeSheetRows(f *excelize.File, sheet string, rows [][]any, start int) {
	for y, row := range rows {
		for x, value := range row {
			cell, err := excelize.CoordinatesToCellName(x+1, y+start)
			if err != nil {
				continue
			}
			_ = f.SetCellValue(sheet, cell, spreadsheetValue(value))
		}
	}
}

// A spreadsheet cell holds 32,767 characters; a longer one makes the workbook
// unopenable rather than merely ugly. Text written before the input limits
// existed can still be longer than that, so it is cut here and says so.
const spreadsheetCellLimit = 32767

func spreadsheetValue(v any) any {
	text, ok := v.(string)
	if !ok || len([]rune(text)) <= spreadsheetCellLimit {
		return v
	}
	return string([]rune(text)[:spreadsheetCellLimit-20]) + " …(이하 생략)"
}
