package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/auth"
	"github.com/hkjang/SecCheck/internal/store"
	"github.com/jackc/pgx/v5"
)

type reviewInput struct {
	ServiceName              string  `json:"service_name"`
	Description              string  `json:"description"`
	ServiceType              string  `json:"service_type"`
	ChangeType               string  `json:"change_type"`
	BuilderID                string  `json:"builder_id"`
	DeveloperID              string  `json:"developer_id"`
	OperatorID               string  `json:"operator_id"`
	Department               string  `json:"department"`
	ReviewerID               string  `json:"reviewer_id"`
	ApproverID               string  `json:"approver_id"`
	PlannedOpenDate          *string `json:"planned_open_date"`
	Exposure                 string  `json:"exposure"`
	HasAdminPage             bool    `json:"has_admin_page"`
	ProcessesPersonalData    bool    `json:"processes_personal_data"`
	ProcessesCreditData      bool    `json:"processes_credit_data"`
	ExternalCustomerService  bool    `json:"external_customer_service"`
	UsesCloud                bool    `json:"uses_cloud"`
	UsesDocker               bool    `json:"uses_docker"`
	UsesKubernetes           bool    `json:"uses_kubernetes"`
	ExternalIntegration      bool    `json:"external_integration"`
	InternetAccess           bool    `json:"internet_access"`
	BusinessCriticality      string  `json:"business_criticality"`
	ManualRuleOverrideReason string  `json:"manual_rule_override_reason"`
}

var reviewColumns = []string{"id", "review_number", "service_name", "service_type", "change_type", "department", "status", "planned_open_date", "requester_id", "reviewer_id", "approver_id", "requester_name", "reviewer_name", "open_change_requests", "overdue_change_requests", "created_at", "updated_at"}

// reviewSorts is an allowlist: the sort key never reaches SQL as free text.
var reviewSorts = map[string]string{
	"updated":   "review_requests.updated_at DESC, review_requests.id DESC",
	"created":   "review_requests.created_at DESC, review_requests.id DESC",
	"open_date": "review_requests.planned_open_date ASC NULLS LAST, review_requests.id DESC",
	"number":    "review_requests.review_number DESC, review_requests.id DESC",
	"service":   "review_requests.service_name ASC, review_requests.id DESC",
	"status":    "review_requests.status ASC, review_requests.updated_at DESC, review_requests.id DESC",
}

// reviewFilter turns the query string into a WHERE clause. It is shared by the
// list, the CSV export and the total count so the three can never disagree.
func (s *Server) reviewFilter(r *http.Request) (string, []any) {
	sess := session(r)
	where, args := accessFilter(sess, 1)
	if hasAnyRole(sess.User, "SECURITY_REVIEWER", "AUDITOR") {
		where = "TRUE"
		args = nil
	}
	query := r.URL.Query()
	add := func(clause string, value any) {
		args = append(args, value)
		where += fmt.Sprintf(" AND "+clause, len(args))
	}
	if v := strings.TrimSpace(query.Get("status")); v != "" {
		if statuses := strings.Split(v, ","); len(statuses) > 1 {
			add("review_requests.status = ANY($%d)", statuses)
		} else {
			add("review_requests.status=$%d", v)
		}
	}
	if v := strings.TrimSpace(query.Get("q")); v != "" {
		args = append(args, "%"+v+"%")
		n := len(args)
		where += fmt.Sprintf(" AND (review_number ILIKE $%d OR service_name ILIKE $%d OR review_requests.department ILIKE $%d)", n, n, n)
	}
	if v := strings.TrimSpace(query.Get("department")); v != "" {
		add("review_requests.department=$%d", v)
	}
	if v := strings.TrimSpace(query.Get("requester_id")); v != "" {
		add("review_requests.requester_id=$%d", v)
	}
	if v := strings.TrimSpace(query.Get("reviewer_id")); v != "" {
		add("review_requests.reviewer_id=$%d", v)
	}
	if v := strings.TrimSpace(query.Get("from")); v != "" {
		add("review_requests.created_at >= $%d::date", v)
	}
	if v := strings.TrimSpace(query.Get("to")); v != "" {
		add("review_requests.created_at < $%d::date + 1", v)
	}
	if strings.TrimSpace(query.Get("overdue")) == "1" {
		where += " AND EXISTS(SELECT 1 FROM change_requests oc WHERE oc.review_request_id=review_requests.id AND oc.status<>'VERIFIED' AND oc.due_date < current_date)"
	}
	if v := strings.TrimSpace(query.Get("mine")); v != "" {
		where += " AND " + myTurnClause(sess, len(args)+1)
		args = append(args, sess.User.ID)
	}
	return where, args
}

const reviewSelect = `SELECT review_requests.id,review_number,service_name,service_type,change_type,review_requests.department,review_requests.status,planned_open_date,requester_id,reviewer_id,approver_id,
        requester.display_name,COALESCE(reviewer.display_name,''),
        (SELECT count(*) FROM change_requests c WHERE c.review_request_id=review_requests.id AND c.status<>'VERIFIED'),
        (SELECT count(*) FROM change_requests c WHERE c.review_request_id=review_requests.id AND c.status<>'VERIFIED' AND c.due_date < current_date),
        review_requests.created_at,review_requests.updated_at
        FROM review_requests JOIN users requester ON requester.id=review_requests.requester_id LEFT JOIN users reviewer ON reviewer.id=review_requests.reviewer_id WHERE `

func (s *Server) listReviewRequests(w http.ResponseWriter, r *http.Request) {
	where, args := s.reviewFilter(r)
	order := reviewSorts["updated"]
	if v := reviewSorts[strings.TrimSpace(r.URL.Query().Get("sort"))]; v != "" {
		order = v
	}
	if r.URL.Query().Get("format") == "csv" {
		rows, err := s.Store.Pool.Query(r.Context(), reviewSelect+where+` ORDER BY `+order+` LIMIT 50000`, args...)
		if err != nil {
			problem(w, 500, "QUERY_FAILED", "심의 목록을 불러오지 못했습니다.", nil)
			return
		}
		records := scanDynamic(rows, reviewColumns)
		_ = s.Store.Audit(r.Context(), auditFrom(r, "EXPORT_REVIEW_LIST", "REVIEW_REQUEST", "", nil, map[string]any{"rows": len(records)}))
		writeCSV(w, "seccheck-reviews", reviewColumns, records)
		return
	}

	limit, offset := parsePage(r)
	var total int64
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM review_requests WHERE `+where, args...).Scan(&total); err != nil {
		problem(w, 500, "QUERY_FAILED", "심의 목록을 불러오지 못했습니다.", nil)
		return
	}
	paged := append(append([]any{}, args...), limit, offset)
	rows, err := s.Store.Pool.Query(r.Context(), reviewSelect+where+fmt.Sprintf(` ORDER BY %s LIMIT $%d OFFSET $%d`, order, len(args)+1, len(args)+2), paged...)
	if err != nil {
		problem(w, 500, "QUERY_FAILED", "심의 목록을 불러오지 못했습니다.", nil)
		return
	}
	items := scanDynamic(rows, reviewColumns)
	jsonResponse(w, 200, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset, "has_more": int64(offset+len(items)) < total})
}

// myTurnClause selects the reviews that are waiting on this specific person,
// which is what the dashboard queue and the "내 차례" filter both mean.
func myTurnClause(sess auth.Session, n int) string {
	var branches []string
	branches = append(branches, fmt.Sprintf(`(review_requests.status IN ('DRAFT','CHANGE_REQUESTED') AND (review_requests.requester_id=$%d OR review_requests.builder_id=$%d OR review_requests.developer_id=$%d OR EXISTS(SELECT 1 FROM review_participants rp WHERE rp.review_request_id=review_requests.id AND rp.user_id=$%d AND rp.participant_role='CONTRIBUTOR')))`, n, n, n, n))
	if hasAnyRole(sess.User, "SECURITY_REVIEWER") {
		branches = append(branches, fmt.Sprintf(`(review_requests.status IN ('SUBMITTED','RESUBMITTED') AND (review_requests.reviewer_id IS NULL OR review_requests.reviewer_id=$%d))`, n))
		branches = append(branches, fmt.Sprintf(`(review_requests.status='REVIEWING' AND review_requests.reviewer_id=$%d)`, n))
	}
	if hasAnyRole(sess.User, "APPROVER") {
		branches = append(branches, fmt.Sprintf(`(review_requests.status='APPROVAL_PENDING' AND (review_requests.approver_id IS NULL OR review_requests.approver_id=$%d))`, n))
	}
	return "(" + strings.Join(branches, " OR ") + ")"
}

// nextReviewNumber allocates the yearly sequence under an advisory lock so
// two concurrent creations cannot claim the same number. The year and the year
// boundary come from the configured display zone: a container running UTC
// would otherwise stamp the first nine hours of a Korean new year with the
// previous year's number, which is exactly when the numbering matters.
func (s *Server) nextReviewNumber(r *http.Request, tx pgx.Tx) (string, error) {
	if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext('seccheck-review-number'))`); err != nil {
		return "", err
	}
	zone := s.Store.Location(r.Context())
	var seq int
	if err := tx.QueryRow(r.Context(), `SELECT count(*)+1 FROM review_requests WHERE created_at >= date_trunc('year', now() AT TIME ZONE $1) AT TIME ZONE $1`, zone.String()).Scan(&seq); err != nil {
		return "", err
	}
	return fmt.Sprintf("SC-%d-%06d", time.Now().In(zone).Year(), seq), nil
}

func validateReviewInput(in reviewInput) map[string]string {
	e := map[string]string{}
	for key, v := range map[string]string{"service_name": in.ServiceName, "description": in.Description, "service_type": in.ServiceType, "change_type": in.ChangeType, "builder_id": in.BuilderID, "developer_id": in.DeveloperID, "department": in.Department, "exposure": in.Exposure} {
		if strings.TrimSpace(v) == "" {
			e[key] = "필수 입력 항목입니다."
		}
	}
	return e
}

func (s *Server) createReviewRequest(w http.ResponseWriter, r *http.Request) {
	var in reviewInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if e := validateReviewInput(in); len(e) > 0 {
		problem(w, 422, "VALIDATION_FAILED", "필수 정보를 확인하세요.", e)
		return
	}
	sess := session(r)
	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		problem(w, 500, "CREATE_FAILED", "심의를 생성하지 못했습니다.", nil)
		return
	}
	defer tx.Rollback(r.Context())
	number, err := s.nextReviewNumber(r, tx)
	if err != nil {
		problem(w, 500, "CREATE_FAILED", "심의번호를 발번하지 못했습니다.", nil)
		return
	}
	id, submissionID := store.NewID(), store.NewID()
	_, err = tx.Exec(r.Context(), `INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,operator_id,department,requester_id,reviewer_id,approver_id,planned_open_date,exposure,has_admin_page,processes_personal_data,processes_credit_data,external_customer_service,uses_cloud,uses_docker,uses_kubernetes,external_integration,internet_access,business_criticality,manual_rule_override_reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),$10,$11,NULLIF($12,''),NULLIF($13,''),NULLIF($14,'')::date,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)`, id, number, in.ServiceName, in.Description, in.ServiceType, in.ChangeType, in.BuilderID, in.DeveloperID, in.OperatorID, in.Department, sess.User.ID, in.ReviewerID, in.ApproverID, dateValue(in.PlannedOpenDate), in.Exposure, in.HasAdminPage, in.ProcessesPersonalData, in.ProcessesCreditData, in.ExternalCustomerService, in.UsesCloud, in.UsesDocker, in.UsesKubernetes, in.ExternalIntegration, in.InternetAccess, in.BusinessCriticality, in.ManualRuleOverrideReason)
	if err != nil {
		problem(w, 500, "CREATE_FAILED", "심의를 생성하지 못했습니다.", err.Error())
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO submissions(id,review_request_id) VALUES($1,$2)`, submissionID, id)
	if err != nil {
		problem(w, 500, "CREATE_FAILED", "제출본을 생성하지 못했습니다.", nil)
		return
	}
	n, err := s.snapshotApplicableItems(r.Context(), tx, submissionID, in)
	if err != nil {
		problem(w, 500, "SNAPSHOT_FAILED", "체크리스트를 배정하지 못했습니다.", err.Error())
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		problem(w, 500, "CREATE_FAILED", "심의를 생성하지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "CREATE_SUBMISSION", "REVIEW_REQUEST", id, nil, map[string]any{"review_number": number, "items": n}))
	if in.ReviewerID != "" {
		s.addTargetedNotification(r.Context(), in.ReviewerID, "REVIEW_ASSIGNED", "심의 담당자 배정", number+" 심의가 배정되었습니다.", "REVIEW_REQUEST", id)
	}
	jsonResponse(w, 201, map[string]any{"id": id, "review_number": number, "submission_id": submissionID, "assigned_items": n})
}

func dateValue(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

type snapshotSource struct {
	ID, TemplateName, Version, ItemCode, Section, Category, Title, Question, Guide, LegalBasis, Example, Severity, AnswerType string
	Required, EvidenceRequired                                                                                                bool
	Rule, Options                                                                                                             []byte
	SortOrder                                                                                                                 int
}

func (s *Server) snapshotApplicableItems(ctx context.Context, tx pgx.Tx, submissionID string, in reviewInput) (int, error) {
	rows, err := tx.Query(ctx, `SELECT i.id,t.name,v.version,i.item_code,COALESCE(sec.name,''),i.category,i.title,i.question,i.guide,i.legal_basis,i.example,i.severity,i.required,i.answer_type,i.evidence_required,i.applicability_rule,i.options_json,i.sort_order FROM checklist_items i JOIN checklist_versions v ON v.id=i.version_id JOIN checklist_templates t ON t.id=v.template_id LEFT JOIN checklist_sections sec ON sec.id=i.section_id WHERE t.active AND v.status='PUBLISHED' AND v.id=(SELECT v2.id FROM checklist_versions v2 WHERE v2.template_id=t.id AND v2.status='PUBLISHED' ORDER BY v2.published_at DESC NULLS LAST,v2.created_at DESC LIMIT 1) ORDER BY t.name,i.sort_order`)
	if err != nil {
		return 0, err
	}
	sources := []snapshotSource{}
	for rows.Next() {
		var x snapshotSource
		if err = rows.Scan(&x.ID, &x.TemplateName, &x.Version, &x.ItemCode, &x.Section, &x.Category, &x.Title, &x.Question, &x.Guide, &x.LegalBasis, &x.Example, &x.Severity, &x.Required, &x.AnswerType, &x.EvidenceRequired, &x.Rule, &x.Options, &x.SortOrder); err != nil {
			rows.Close()
			return 0, err
		}
		sources = append(sources, x)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	n := 0
	fields := reviewFields(in)
	for _, x := range sources {
		if !categoryApplies(x.Category, in) || !evaluateRule(x.Rule, fields) {
			continue
		}
		_, err = tx.Exec(ctx, `INSERT INTO submission_items(id,submission_id,source_item_id,template_name,template_version,item_code,section,category,title,question,guide,legal_basis,example,severity,required,answer_type,evidence_required,options_json,sort_order) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`, store.NewID(), submissionID, x.ID, x.TemplateName, x.Version, x.ItemCode, x.Section, x.Category, x.Title, x.Question, x.Guide, x.LegalBasis, x.Example, x.Severity, x.Required, x.AnswerType, x.EvidenceRequired, x.Options, x.SortOrder)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func categoryApplies(category string, in reviewInput) bool {
	switch strings.ToUpper(category) {
	case "PRIVACY", "PERSONAL_DATA":
		return in.ProcessesPersonalData || in.ProcessesCreditData
	case "CLOUD":
		return in.UsesCloud
	case "DOCKER", "CONTAINER_DOCKER":
		return in.UsesDocker
	case "KUBERNETES", "CONTAINER_KUBERNETES":
		return in.UsesKubernetes
	default:
		return true
	}
}
func reviewFields(in reviewInput) map[string]any {
	return map[string]any{"service_type": in.ServiceType, "change_type": in.ChangeType, "exposure": in.Exposure, "has_admin_page": in.HasAdminPage, "processes_personal_data": in.ProcessesPersonalData, "processes_credit_data": in.ProcessesCreditData, "external_customer_service": in.ExternalCustomerService, "uses_cloud": in.UsesCloud, "uses_docker": in.UsesDocker, "uses_kubernetes": in.UsesKubernetes, "external_integration": in.ExternalIntegration, "internet_access": in.InternetAccess, "business_criticality": in.BusinessCriticality}
}

func evaluateRule(raw []byte, fields map[string]any) bool {
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		return true
	}
	var node any
	if json.Unmarshal(raw, &node) != nil {
		return false
	}
	return evalNode(node, fields)
}
func evalNode(node any, fields map[string]any) bool {
	m, ok := node.(map[string]any)
	if !ok {
		return true
	}
	if all, ok := m["all"].([]any); ok {
		for _, v := range all {
			if !evalNode(v, fields) {
				return false
			}
		}
		return true
	}
	if any, ok := m["any"].([]any); ok {
		for _, v := range any {
			if evalNode(v, fields) {
				return true
			}
		}
		return false
	}
	if not, ok := m["not"]; ok {
		return !evalNode(not, fields)
	}
	field, _ := m["field"].(string)
	op, _ := m["operator"].(string)
	actual, exists := fields[field]
	if strings.EqualFold(op, "exists") {
		return exists == boolValue(m["value"])
	}
	if !exists {
		return false
	}
	expected := m["value"]
	switch strings.ToLower(op) {
	case "eq", "=", "":
		return fmt.Sprint(actual) == fmt.Sprint(expected)
	case "neq", "!=":
		return fmt.Sprint(actual) != fmt.Sprint(expected)
	case "in":
		values, ok := expected.([]any)
		if !ok {
			return false
		}
		for _, v := range values {
			if fmt.Sprint(actual) == fmt.Sprint(v) {
				return true
			}
		}
		return false
	case "contains":
		return strings.Contains(fmt.Sprint(actual), fmt.Sprint(expected))
	case "gt", "gte", "lt", "lte":
		a, aErr := strconv.ParseFloat(fmt.Sprint(actual), 64)
		b, bErr := strconv.ParseFloat(fmt.Sprint(expected), 64)
		if aErr != nil || bErr != nil {
			return false
		}
		switch strings.ToLower(op) {
		case "gt":
			return a > b
		case "gte":
			return a >= b
		case "lt":
			return a < b
		default:
			return a <= b
		}
	}
	return false
}
func boolValue(v any) bool { b, _ := v.(bool); return b }

func (s *Server) getReviewRequest(w http.ResponseWriter, r *http.Request) {
	if !s.canAccessReview(r.Context(), session(r), r.PathValue("id")) {
		problem(w, 404, "NOT_FOUND", "심의를 찾을 수 없습니다.", nil)
		return
	}
	row := s.Store.Pool.QueryRow(r.Context(), `SELECT to_jsonb(r)-'description'||jsonb_build_object('description',r.description,'requester_name',ru.display_name,'reviewer_name',rv.display_name,'approver_name',ap.display_name,'progress',(SELECT jsonb_build_object('total',count(*),'answered',count(resp.id),'evidence',count(DISTINCT ev.id)) FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id LEFT JOIN responses resp ON resp.submission_item_id=si.id LEFT JOIN evidences ev ON ev.submission_item_id=si.id AND ev.deleted_at IS NULL WHERE sub.review_request_id=r.id AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=r.id)),'risk_score',(SELECT COALESCE(sum(CASE si.severity WHEN 'CRITICAL' THEN 10 WHEN 'HIGH' THEN 7 WHEN 'MEDIUM' THEN 3 ELSE 1 END) FILTER(WHERE rr.result IN ('INSUFFICIENT','NON_COMPLIANT','CONDITIONAL','RECHECK')),0) FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id LEFT JOIN review_results rr ON rr.submission_item_id=si.id WHERE sub.review_request_id=r.id AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=r.id))) FROM review_requests r JOIN users ru ON ru.id=r.requester_id LEFT JOIN users rv ON rv.id=r.reviewer_id LEFT JOIN users ap ON ap.id=r.approver_id WHERE r.id=$1`, r.PathValue("id"))
	var data []byte
	if err := row.Scan(&data); err != nil {
		problem(w, 404, "NOT_FOUND", "심의를 찾을 수 없습니다.", nil)
		return
	}
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	var total, compliant, conditional, insufficient, nonCompliant, na, followUp int
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*),count(*) FILTER(WHERE rr.result='COMPLIANT'),count(*) FILTER(WHERE rr.result='CONDITIONAL'),count(*) FILTER(WHERE rr.result='INSUFFICIENT'),count(*) FILTER(WHERE rr.result='NON_COMPLIANT'),count(*) FILTER(WHERE rr.result='NA_ACCEPTED' OR resp.applicability='N/A'),count(*) FILTER(WHERE COALESCE(rr.follow_up,'')<>'') FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id LEFT JOIN responses resp ON resp.submission_item_id=si.id LEFT JOIN review_results rr ON rr.submission_item_id=si.id WHERE sub.review_request_id=$1 AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$1)`, r.PathValue("id")).Scan(&total, &compliant, &conditional, &insufficient, &nonCompliant, &na, &followUp)
	naRatio := 0.0
	if total > 0 {
		naRatio = float64(na) * 100 / float64(total)
	}
	out["result_summary"] = map[string]any{"total": total, "compliant": compliant, "conditional": conditional, "insufficient": insufficient, "non_compliant": nonCompliant, "na": na, "na_ratio": naRatio, "follow_up": followUp}
	out["template_versions"] = s.snapshotTemplateVersions(r, r.PathValue("id"))
	_ = s.Store.Audit(r.Context(), auditFrom(r, "VIEW_SUBMISSION", "REVIEW_REQUEST", r.PathValue("id"), nil, nil))
	jsonResponse(w, 200, out)
}

func (s *Server) updateReviewRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.canEditReview(r.Context(), session(r), id) {
		problem(w, 403, "FORBIDDEN", "이 심의를 수정할 수 없습니다.", nil)
		return
	}
	var in struct {
		Description         string `json:"description"`
		ReviewerID          string `json:"reviewer_id"`
		ApproverID          string `json:"approver_id"`
		PlannedOpenDate     string `json:"planned_open_date"`
		BusinessCriticality string `json:"business_criticality"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE review_requests SET description=COALESCE(NULLIF($2,''),description),reviewer_id=COALESCE(NULLIF($3,''),reviewer_id),approver_id=COALESCE(NULLIF($4,''),approver_id),planned_open_date=COALESCE(NULLIF($5,'')::date,planned_open_date),business_criticality=COALESCE(NULLIF($6,''),business_criticality),updated_at=now() WHERE id=$1 AND status IN ('DRAFT','CHANGE_REQUESTED')`, id, in.Description, in.ReviewerID, in.ApproverID, in.PlannedOpenDate, in.BusinessCriticality)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "STATE_CONFLICT", "현재 상태에서는 수정할 수 없습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPDATE_SUBMISSION", "REVIEW_REQUEST", id, nil, in))
	if in.ReviewerID != "" {
		s.addTargetedNotification(r.Context(), in.ReviewerID, "REVIEW_ASSIGNED", "심의 담당자 배정", "배정된 심의를 확인하세요.", "REVIEW_REQUEST", id)
	}
	jsonResponse(w, 200, map[string]any{"id": id})
}

// snapshotTemplateVersions reports which template version each part of the
// checklist was taken from and whether a newer one has been published since.
// The snapshot deliberately never moves, but nobody was told that, so a
// reviewer comparing a review against today's checklist had no way to know
// they were looking at an older edition.
func (s *Server) snapshotTemplateVersions(r *http.Request, reviewID string) []map[string]any {
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT DISTINCT si.template_name,si.template_version,
                COALESCE((SELECT v.version FROM checklist_versions v JOIN checklist_templates t ON t.id=v.template_id
                          WHERE t.name=si.template_name AND v.status='PUBLISHED'
                          ORDER BY v.published_at DESC NULLS LAST, v.created_at DESC LIMIT 1),'') AS current_version
                FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id
                WHERE sub.review_request_id=$1 AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$1)
                ORDER BY si.template_name`, reviewID)
	if err != nil {
		return []map[string]any{}
	}
	out := scanDynamic(rows, []string{"template_name", "snapshot_version", "current_version"})
	for _, entry := range out {
		snapshot, _ := entry["snapshot_version"].(string)
		current, _ := entry["current_version"].(string)
		entry["outdated"] = current != "" && current != snapshot
	}
	return out
}

// reviewHistory assembles what happened to one review from the audit log.
// Everything was already recorded, but only a system administrator or auditor
// could look at it, so the requester could not answer "when did the change
// request arrive" or "why was this rejected" from their own review.
func (s *Server) reviewHistory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.canAccessReview(r.Context(), session(r), id) {
		problem(w, 404, "NOT_FOUND", "심의를 찾을 수 없습니다.", nil)
		return
	}
	limit, offset := parsePage(r)
	// The events that belong to a review are the ones aimed at it and at the
	// rows that hang off it.
	scope := `(a.target_id=$1
                OR a.target_id IN (SELECT si.id FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id WHERE sub.review_request_id=$1)
                OR a.target_id IN (SELECT e.id FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id JOIN evidences e ON e.submission_item_id=si.id WHERE sub.review_request_id=$1)
                OR a.target_id IN (SELECT c.id FROM change_requests c WHERE c.review_request_id=$1))`
	var total int64
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM audit_logs a WHERE `+scope, id).Scan(&total); err != nil {
		problem(w, 500, "QUERY_FAILED", "심의 이력을 불러오지 못했습니다.", nil)
		return
	}
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT a.timestamp,a.event_type,a.user_name,a.target_type,a.target_id,a.result,
                COALESCE((SELECT si.item_code FROM submission_items si WHERE si.id=a.target_id),'') AS item_code
                FROM audit_logs a WHERE `+scope+` ORDER BY a.timestamp DESC LIMIT $2 OFFSET $3`, id, limit, offset)
	if err != nil {
		problem(w, 500, "QUERY_FAILED", "심의 이력을 불러오지 못했습니다.", nil)
		return
	}
	items := scanDynamic(rows, []string{"timestamp", "event_type", "user_name", "target_type", "target_id", "result", "item_code"})
	for _, item := range items {
		if code, ok := item["event_type"].(string); ok {
			item["event_label"] = auditEventLabels[code]
		}
	}
	jsonResponse(w, 200, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset, "has_more": int64(offset+len(items)) < total})
}

func (s *Server) listSubmissionItems(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.canAccessReview(r.Context(), session(r), id) {
		problem(w, 404, "NOT_FOUND", "심의를 찾을 수 없습니다.", nil)
		return
	}
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT si.id,si.template_name,si.template_version,si.item_code,si.section,si.category,si.title,si.question,si.guide,si.legal_basis,si.example,si.severity,si.required,si.answer_type,si.evidence_required,si.options_json,si.sort_order,COALESCE(to_jsonb(resp),'{}'),COALESCE(to_jsonb(rr),'{}'),COALESCE((SELECT jsonb_agg(to_jsonb(e)-'stored_filename' ORDER BY e.created_at) FROM evidences e WHERE e.submission_item_id=si.id AND e.deleted_at IS NULL),'[]'),COALESCE((SELECT jsonb_agg(to_jsonb(cr) ORDER BY cr.created_at) FROM change_requests cr WHERE cr.submission_item_id=si.id),'[]'),COALESCE((SELECT jsonb_agg(to_jsonb(c)||jsonb_build_object('author_name',u.display_name) ORDER BY c.created_at) FROM comments c JOIN users u ON u.id=c.author_id WHERE c.submission_item_id=si.id),'[]') FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id LEFT JOIN responses resp ON resp.submission_item_id=si.id LEFT JOIN review_results rr ON rr.submission_item_id=si.id WHERE sub.review_request_id=$1 AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$1) ORDER BY si.template_name,si.sort_order`, id)
	if err != nil {
		problem(w, 500, "QUERY_FAILED", "체크리스트를 불러오지 못했습니다.", nil)
		return
	}
	jsonResponse(w, 200, scanDynamic(rows, []string{"id", "template_name", "template_version", "item_code", "section", "category", "title", "question", "guide", "legal_basis", "example", "severity", "required", "answer_type", "evidence_required", "options", "sort_order", "response", "review_result", "evidences", "change_requests", "comments"}))
}

func (s *Server) addComment(w http.ResponseWriter, r *http.Request) {
	reviewID, itemID := r.PathValue("id"), r.PathValue("itemID")
	if !hasAnyRole(session(r).User, "REQUESTER", "CONTRIBUTOR", "SECURITY_REVIEWER", "APPROVER") {
		problem(w, 403, "FORBIDDEN", "읽기 전용 역할은 코멘트를 작성할 수 없습니다.", nil)
		return
	}
	if !s.canAccessReview(r.Context(), session(r), reviewID) || !s.itemBelongsToReview(r.Context(), itemID, reviewID) {
		problem(w, 404, "NOT_FOUND", "체크리스트 항목을 찾을 수 없습니다.", nil)
		return
	}
	var in struct {
		Body string `json:"body"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Body = strings.TrimSpace(in.Body)
	if in.Body == "" || len([]rune(in.Body)) > 4000 {
		problem(w, 422, "VALIDATION_FAILED", "코멘트는 1~4000자로 입력하세요.", nil)
		return
	}
	id := store.NewID()
	_, err := s.Store.Pool.Exec(r.Context(), `INSERT INTO comments(id,submission_item_id,author_id,body) VALUES($1,$2,$3,$4)`, id, itemID, session(r).User.ID, in.Body)
	if err != nil {
		problem(w, 500, "CREATE_FAILED", "코멘트를 저장하지 못했습니다.", nil)
		return
	}
	s.notifyComment(r, reviewID, itemID, in.Body)
	_ = s.Store.Audit(r.Context(), auditFrom(r, "CREATE_COMMENT", "SUBMISSION_ITEM", itemID, nil, map[string]any{"comment_id": id}))
	jsonResponse(w, 201, map[string]string{"id": id})
}

// notifyComment tells the other side of the review that a question was asked.
// Comments used to notify nobody, so a reviewer's question sat on an item
// until the author happened to open it.
func (s *Server) notifyComment(r *http.Request, reviewID, itemID, body string) {
	author := session(r).User
	var number, service, requester, reviewer, builder, developer string
	var assignee *string
	err := s.Store.Pool.QueryRow(r.Context(), `SELECT rq.review_number,rq.service_name,rq.requester_id,COALESCE(rq.reviewer_id,''),rq.builder_id,rq.developer_id,
                (SELECT resp.assigned_to FROM responses resp WHERE resp.submission_item_id=$2)
                FROM review_requests rq WHERE rq.id=$1`, reviewID, itemID).
		Scan(&number, &service, &requester, &reviewer, &builder, &developer, &assignee)
	if err != nil {
		return
	}
	var itemCode string
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT item_code FROM submission_items WHERE id=$1`, itemID).Scan(&itemCode)

	// The people who need to know are the ones on the opposite side of the
	// conversation, plus whoever owns the item.
	recipients := map[string]bool{}
	if author.ID == reviewer {
		recipients[requester] = true
		recipients[builder] = true
		recipients[developer] = true
	} else {
		recipients[reviewer] = true
	}
	if assignee != nil {
		recipients[*assignee] = true
	}
	delete(recipients, author.ID)
	delete(recipients, "")

	title := "체크리스트 코멘트"
	message := fmt.Sprintf("%s(%s) %s 항목에 %s님이 코멘트를 남겼습니다.\n\n%s", number, service, itemCode, author.DisplayName, truncate(body, 300))
	for recipient := range recipients {
		s.addTargetedNotification(r.Context(), recipient, "COMMENT_ADDED", title, message, "REVIEW_REQUEST", reviewID)
	}
}

func (s *Server) saveResponse(w http.ResponseWriter, r *http.Request) {
	reviewID, itemID := r.PathValue("id"), r.PathValue("itemID")
	if !s.canEditReview(r.Context(), session(r), reviewID) {
		problem(w, 403, "FORBIDDEN", "이 심의를 작성할 수 없습니다.", nil)
		return
	}
	var in struct {
		Answer         any    `json:"answer"`
		Applicability  string `json:"applicability"`
		SelfAssessment string `json:"self_assessment"`
		CurrentState   string `json:"current_state"`
		NAReason       string `json:"na_reason"`
		ActionPlan     string `json:"action_plan"`
		AssignedTo     string `json:"assigned_to"`
		// ExpectedUpdatedAt is the version the editor loaded. A checklist is
		// filled in by several people at once and the editor auto-saves, so
		// without it the last keystroke anywhere silently wins.
		ExpectedUpdatedAt string `json:"expected_updated_at"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !contains([]string{"Y", "N", "N/A"}, in.Applicability) {
		problem(w, 422, "VALIDATION_FAILED", "적용 여부는 Y, N 또는 N/A여야 합니다.", nil)
		return
	}
	if in.SelfAssessment != "" && !contains([]string{"COMPLIANT", "INSUFFICIENT", "N/A"}, in.SelfAssessment) {
		problem(w, 422, "VALIDATION_FAILED", "자체 판단 값을 확인하세요.", nil)
		return
	}
	if in.Applicability == "N/A" && strings.TrimSpace(in.NAReason) == "" {
		problem(w, 422, "NA_REASON_REQUIRED", "N/A 선택 시 사유가 필요합니다.", map[string]string{"na_reason": "필수 입력 항목입니다."})
		return
	}
	if conflict, ok := s.responseConflict(r, itemID, in.ExpectedUpdatedAt); ok {
		problem(w, 409, "RESPONSE_CONFLICT", "다른 사용자가 이 항목을 먼저 저장했습니다. 최신 내용을 확인한 뒤 다시 저장하세요.", conflict)
		return
	}
	answer, _ := json.Marshal(in.Answer)
	id := store.NewID()
	var savedAt time.Time
	err := s.Store.Pool.QueryRow(r.Context(), `INSERT INTO responses(id,submission_item_id,answer_json,applicability,self_assessment,current_state,na_reason,action_plan,assigned_to,updated_by) SELECT $1,si.id,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9 FROM submission_items si JOIN submissions sub ON sub.id=si.submission_id WHERE si.id=$10 AND sub.review_request_id=$11 AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$11) ON CONFLICT(submission_item_id) DO UPDATE SET answer_json=EXCLUDED.answer_json,applicability=EXCLUDED.applicability,self_assessment=EXCLUDED.self_assessment,current_state=EXCLUDED.current_state,na_reason=EXCLUDED.na_reason,action_plan=EXCLUDED.action_plan,assigned_to=EXCLUDED.assigned_to,updated_by=EXCLUDED.updated_by,updated_at=now() RETURNING updated_at`, id, answer, in.Applicability, in.SelfAssessment, in.CurrentState, in.NAReason, in.ActionPlan, in.AssignedTo, session(r).User.ID, itemID, reviewID).Scan(&savedAt)
	if err != nil {
		problem(w, 404, "NOT_FOUND", "체크리스트 항목을 찾을 수 없습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPDATE_RESPONSE", "SUBMISSION_ITEM", itemID, nil, map[string]any{"applicability": in.Applicability, "self_assessment": in.SelfAssessment, "assigned_to": in.AssignedTo}))
	jsonResponse(w, 200, map[string]any{"saved_at": savedAt, "updated_at": savedAt})
}

// responseConflict reports whether the stored answer has moved on since the
// editor loaded it, and returns what is there now so the UI can show both
// sides rather than just refusing. An empty expectation means the caller is
// not participating in conflict detection, which keeps older clients working.
func (s *Server) responseConflict(r *http.Request, itemID, expected string) (map[string]any, bool) {
	if strings.TrimSpace(expected) == "" {
		return nil, false
	}
	want, err := time.Parse(time.RFC3339Nano, expected)
	if err != nil {
		return nil, false
	}
	var current time.Time
	var by, applicability, selfAssessment, currentState, naReason, actionPlan string
	err = s.Store.Pool.QueryRow(r.Context(), `SELECT resp.updated_at,COALESCE(u.display_name,''),resp.applicability,resp.self_assessment,resp.current_state,resp.na_reason,resp.action_plan
                FROM responses resp LEFT JOIN users u ON u.id=resp.updated_by WHERE resp.submission_item_id=$1`, itemID).
		Scan(&current, &by, &applicability, &selfAssessment, &currentState, &naReason, &actionPlan)
	if err != nil || current.Equal(want) {
		return nil, false
	}
	return map[string]any{
		"updated_at": current, "updated_by": by,
		"applicability": applicability, "self_assessment": selfAssessment,
		"current_state": currentState, "na_reason": naReason, "action_plan": actionPlan,
	}, true
}

func (s *Server) reviewResultConflict(r *http.Request, itemID, expected string) (map[string]any, bool) {
	if strings.TrimSpace(expected) == "" {
		return nil, false
	}
	want, err := time.Parse(time.RFC3339Nano, expected)
	if err != nil {
		return nil, false
	}
	var current time.Time
	var by, result, opinion, adequacy, followUp string
	err = s.Store.Pool.QueryRow(r.Context(), `SELECT rr.updated_at,COALESCE(u.display_name,''),rr.result,rr.opinion,rr.evidence_adequacy,rr.follow_up
                FROM review_results rr LEFT JOIN users u ON u.id=rr.reviewer_id WHERE rr.submission_item_id=$1`, itemID).
		Scan(&current, &by, &result, &opinion, &adequacy, &followUp)
	if err != nil || current.Equal(want) {
		return nil, false
	}
	return map[string]any{"updated_at": current, "updated_by": by, "result": result, "opinion": opinion, "evidence_adequacy": adequacy, "follow_up": followUp}, true
}

func (s *Server) submitReview(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.canEditReview(r.Context(), session(r), id) {
		problem(w, 403, "FORBIDDEN", "이 심의를 제출할 수 없습니다.", nil)
		return
	}
	issues, err := s.validateSubmission(r.Context(), id)
	if err != nil {
		problem(w, 500, "VALIDATION_FAILED", "제출 검증에 실패했습니다.", nil)
		return
	}
	if len(issues) > 0 {
		problem(w, 422, "SUBMISSION_INCOMPLETE", "누락된 항목을 확인하세요.", issues)
		return
	}
	var current string
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT status FROM review_requests WHERE id=$1`, id).Scan(&current)
	next := "SUBMITTED"
	event := "SUBMIT"
	if current == "CHANGE_REQUESTED" {
		next = "RESUBMITTED"
		event = "RESUBMIT"
	}
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE review_requests SET status=$2,first_submitted_at=COALESCE(first_submitted_at,now()),final_submitted_at=now(),updated_at=now() WHERE id=$1 AND status IN ('DRAFT','CHANGE_REQUESTED')`, id, next)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "STATE_CONFLICT", "현재 상태에서는 제출할 수 없습니다.", nil)
		return
	}
	_, _ = s.Store.Pool.Exec(r.Context(), `UPDATE submissions SET status=$2,submitted_by=$3,submitted_at=now() WHERE review_request_id=$1 AND revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$1)`, id, next, session(r).User.ID)
	s.notifyReviewer(r.Context(), id, "REVIEW_SUBMITTED", "")
	_ = s.Store.Audit(r.Context(), auditFrom(r, event, "REVIEW_REQUEST", id, map[string]any{"status": current}, map[string]any{"status": next}))
	jsonResponse(w, 200, map[string]any{"status": next})
}

func (s *Server) validateSubmission(ctx context.Context, id string) ([]map[string]any, error) {
	rows, err := s.Store.Pool.Query(ctx, `SELECT si.id,si.item_code,si.title,si.required,si.evidence_required,si.answer_type,si.options_json,COALESCE(resp.answer_json,'{}'),COALESCE(resp.applicability,''),COALESCE(resp.self_assessment,''),COALESCE(resp.na_reason,''),(SELECT count(*) FROM evidences e WHERE e.submission_item_id=si.id AND e.deleted_at IS NULL),(SELECT count(*) FROM evidences e WHERE e.submission_item_id=si.id AND e.deleted_at IS NULL AND e.scan_status NOT IN ('CLEAN','SKIPPED')) FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id LEFT JOIN responses resp ON resp.submission_item_id=si.id WHERE sub.review_request_id=$1 AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$1)`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	issues := []map[string]any{}
	count := 0
	for rows.Next() {
		count++
		var itemID, code, title string
		var required, evidenceRequired bool
		var answerType, applicability, selfAssessment, na string
		var options, answer []byte
		var ev, bad int
		if err = rows.Scan(&itemID, &code, &title, &required, &evidenceRequired, &answerType, &options, &answer, &applicability, &selfAssessment, &na, &ev, &bad); err != nil {
			return nil, err
		}
		reasons := []string{}
		if required && applicability == "" {
			reasons = append(reasons, "적용 여부 미선택")
		}
		if required && applicability != "N/A" && selfAssessment == "" {
			reasons = append(reasons, "자체 판단 누락")
		}
		if required && applicability != "N/A" {
			if reason := s.validateTypedAnswer(ctx, answerType, answer, options, ev); reason != "" {
				reasons = append(reasons, reason)
			}
		}
		if applicability == "N/A" && strings.TrimSpace(na) == "" {
			reasons = append(reasons, "N/A 사유 누락")
		}
		if evidenceRequired && applicability != "N/A" && ev == 0 {
			reasons = append(reasons, "필수 증적 누락")
		}
		if bad > 0 {
			reasons = append(reasons, "악성코드 검사 미완료")
		}
		if len(reasons) > 0 {
			issues = append(issues, map[string]any{"item_id": itemID, "item_code": code, "title": title, "reasons": reasons})
		}
	}
	if count == 0 {
		issues = append(issues, map[string]any{"item_code": "-", "title": "체크리스트", "reasons": []string{"배정된 체크리스트가 없습니다. 관리자가 게시된 템플릿을 확인해야 합니다."}})
	}
	var open int
	if err = s.Store.Pool.QueryRow(ctx, `SELECT count(*) FROM change_requests WHERE review_request_id=$1 AND status='OPEN'`, id).Scan(&open); err == nil && open > 0 {
		issues = append(issues, map[string]any{"item_code": "-", "title": "보완 요청", "reasons": []string{fmt.Sprintf("미완료 보완 요청 %d건", open)}})
	}
	var workflow struct {
		ApprovalEnabled           bool `json:"approval_enabled"`
		RequireReviewerAssignment bool `json:"require_reviewer_assignment"`
	}
	_, _ = s.Store.Setting(ctx, "workflow", &workflow)
	var reviewer, approver string
	if err = s.Store.Pool.QueryRow(ctx, `SELECT COALESCE(reviewer_id,''),COALESCE(approver_id,'') FROM review_requests WHERE id=$1`, id).Scan(&reviewer, &approver); err != nil {
		return nil, err
	}
	if workflow.RequireReviewerAssignment && reviewer == "" {
		issues = append(issues, map[string]any{"item_code": "-", "title": "검토자", "reasons": []string{"검토자 배정이 필요합니다."}})
	}
	if workflow.ApprovalEnabled && approver == "" {
		issues = append(issues, map[string]any{"item_code": "-", "title": "승인자", "reasons": []string{"승인 프로세스가 활성화되어 승인자 배정이 필요합니다."}})
	}
	return issues, rows.Err()
}

func (s *Server) validateTypedAnswer(ctx context.Context, answerType string, raw, optionsRaw []byte, evidenceCount int) string {
	if contains([]string{"YNNA", "ASSESSMENT", "GUIDE", "AUTOCALC"}, answerType) {
		return ""
	}
	if answerType == "FILE" {
		if evidenceCount == 0 {
			return "파일 답변 누락"
		}
		return ""
	}
	if emptyAnswer(raw) {
		return "필수 답변 누락"
	}
	var decoded any
	if json.Unmarshal(raw, &decoded) != nil {
		return "답변 형식 오류"
	}
	m, _ := decoded.(map[string]any)
	value := decoded
	if m != nil {
		value = m["value"]
	}
	switch answerType {
	case "NUMBER":
		if _, ok := value.(float64); !ok {
			return "숫자 답변 형식 오류"
		}
	case "DATE":
		if _, err := time.Parse("2006-01-02", fmt.Sprint(value)); err != nil {
			return "날짜 답변 형식 오류"
		}
	case "URL":
		u, err := url.ParseRequestURI(fmt.Sprint(value))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return "URL 답변 형식 오류"
		}
	case "USER":
		var active bool
		_ = s.Store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND active)`, fmt.Sprint(value)).Scan(&active)
		if !active {
			return "유효한 담당자를 선택하세요"
		}
	case "SINGLE_SELECT", "MULTI_SELECT":
		allowed := optionValues(optionsRaw)
		selected := []string{}
		if answerType == "SINGLE_SELECT" {
			selected = []string{fmt.Sprint(value)}
		} else if values, ok := m["values"].([]any); ok {
			for _, v := range values {
				selected = append(selected, fmt.Sprint(v))
			}
		}
		if len(selected) == 0 {
			return "선택 답변 누락"
		}
		for _, selectedValue := range selected {
			if !contains(allowed, selectedValue) {
				return "허용되지 않은 선택값"
			}
		}
	case "REPEAT_TABLE":
		rows, ok := m["rows"].([]any)
		if !ok || len(rows) == 0 {
			return "반복 목록 누락"
		}
	}
	return ""
}

func optionValues(raw []byte) []string {
	var options []any
	_ = json.Unmarshal(raw, &options)
	out := []string{}
	for _, option := range options {
		if text, ok := option.(string); ok {
			out = append(out, text)
			continue
		}
		if m, ok := option.(map[string]any); ok {
			value := fmt.Sprint(m["value"])
			if value == "<nil>" || value == "" {
				value = fmt.Sprint(m["label"])
			}
			out = append(out, value)
		}
	}
	return out
}

func emptyAnswer(raw []byte) bool {
	var v any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return true
	}
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(x) == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		if len(x) == 0 {
			return true
		}
		for _, v := range x {
			switch y := v.(type) {
			case string:
				if strings.TrimSpace(y) != "" {
					return false
				}
			case []any:
				if len(y) > 0 {
					return false
				}
			case nil:
			default:
				return false
			}
		}
		return true
	}
	return false
}

func (s *Server) beginReview(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sess := session(r)
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE review_requests SET status='REVIEWING',reviewer_id=COALESCE(reviewer_id,$2),updated_at=now() WHERE id=$1 AND status IN ('SUBMITTED','RESUBMITTED') AND (reviewer_id IS NULL OR reviewer_id=$2)`, id, sess.User.ID)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "STATE_CONFLICT", "심의를 시작할 수 없습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "BEGIN_REVIEW", "REVIEW_REQUEST", id, nil, map[string]string{"status": "REVIEWING"}))
	jsonResponse(w, 200, map[string]string{"status": "REVIEWING"})
}

func (s *Server) saveReviewResult(w http.ResponseWriter, r *http.Request) {
	id, itemID := r.PathValue("id"), r.PathValue("itemID")
	if !s.canReview(r.Context(), session(r), id) {
		problem(w, 403, "FORBIDDEN", "이 심의를 검토할 수 없습니다.", nil)
		return
	}
	var in struct {
		FinalApplicability string `json:"final_applicability"`
		Result             string `json:"result"`
		Opinion            string `json:"opinion"`
		EvidenceAdequacy   string `json:"evidence_adequacy"`
		FollowUp           string `json:"follow_up"`
		NAApproved         *bool  `json:"na_approved"`
		ExpectedUpdatedAt  string `json:"expected_updated_at"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	valid := map[string]bool{"COMPLIANT": true, "CONDITIONAL": true, "INSUFFICIENT": true, "NON_COMPLIANT": true, "NA_ACCEPTED": true, "RECHECK": true}
	if !valid[in.Result] {
		problem(w, 422, "VALIDATION_FAILED", "검토 결과를 선택하세요.", nil)
		return
	}
	// Two reviewers can hold the same review open, so the same protection the
	// author side has applies here.
	if conflict, ok := s.reviewResultConflict(r, itemID, in.ExpectedUpdatedAt); ok {
		problem(w, 409, "REVIEW_RESULT_CONFLICT", "다른 검토자가 이 항목을 먼저 저장했습니다. 최신 내용을 확인한 뒤 다시 저장하세요.", conflict)
		return
	}
	var savedAt time.Time
	err := s.Store.Pool.QueryRow(r.Context(), `INSERT INTO review_results(id,submission_item_id,reviewer_id,final_applicability,result,opinion,evidence_adequacy,na_approved,follow_up) SELECT $1,si.id,$2,$3,$4,$5,$6,$7,$8 FROM submission_items si JOIN submissions sub ON sub.id=si.submission_id JOIN review_requests rq ON rq.id=sub.review_request_id WHERE si.id=$9 AND sub.review_request_id=$10 AND rq.status='REVIEWING' AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$10) ON CONFLICT(submission_item_id) DO UPDATE SET reviewer_id=EXCLUDED.reviewer_id,final_applicability=EXCLUDED.final_applicability,result=EXCLUDED.result,opinion=EXCLUDED.opinion,evidence_adequacy=EXCLUDED.evidence_adequacy,na_approved=EXCLUDED.na_approved,follow_up=EXCLUDED.follow_up,updated_at=now() RETURNING updated_at`, store.NewID(), session(r).User.ID, in.FinalApplicability, in.Result, in.Opinion, in.EvidenceAdequacy, in.NAApproved, in.FollowUp, itemID, id).Scan(&savedAt)
	if err != nil {
		problem(w, 404, "NOT_FOUND", "검토 항목을 찾을 수 없습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "REVIEW_ITEM", "SUBMISSION_ITEM", itemID, nil, in))
	jsonResponse(w, 200, map[string]any{"saved_at": savedAt, "updated_at": savedAt})
}

func (s *Server) createChangeRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.canReview(r.Context(), session(r), id) {
		problem(w, 403, "FORBIDDEN", "이 심의를 검토할 수 없습니다.", nil)
		return
	}
	var in struct {
		ItemID     string `json:"item_id"`
		Reason     string `json:"reason"`
		AssigneeID string `json:"assignee_id"`
		DueDate    string `json:"due_date"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.ItemID == "" || strings.TrimSpace(in.Reason) == "" {
		problem(w, 422, "VALIDATION_FAILED", "항목과 보완 사유가 필요합니다.", nil)
		return
	}
	if !s.itemBelongsToLatestSubmission(r.Context(), in.ItemID, id) {
		problem(w, 404, "NOT_FOUND", "현재 제출본의 검토 항목을 찾을 수 없습니다.", nil)
		return
	}
	crid := store.NewID()
	tx, err := s.Store.Pool.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO change_requests(id,review_request_id,submission_item_id,reason,requester_id,assignee_id,due_date) VALUES($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,'')::date)`, crid, id, in.ItemID, in.Reason, session(r).User.ID, in.AssigneeID, in.DueDate)
		if err == nil {
			tag, updateErr := tx.Exec(r.Context(), `UPDATE review_requests SET status='CHANGE_REQUESTED',updated_at=now() WHERE id=$1 AND status='REVIEWING'`, id)
			err = updateErr
			if err == nil && tag.RowsAffected() == 0 {
				err = errors.New("review is not in REVIEWING state")
			}
		}
		if err == nil {
			err = tx.Commit(r.Context())
		} else {
			_ = tx.Rollback(r.Context())
		}
	}
	if err != nil {
		problem(w, 500, "CREATE_FAILED", "보완 요청을 만들지 못했습니다.", nil)
		return
	}
	recipient := in.AssigneeID
	if recipient == "" {
		_ = s.Store.Pool.QueryRow(r.Context(), `SELECT requester_id FROM review_requests WHERE id=$1`, id).Scan(&recipient)
	}
	s.addTargetedNotification(r.Context(), recipient, "CHANGE_REQUEST", "보완 요청", in.Reason, "REVIEW_REQUEST", id)
	_ = s.Store.Audit(r.Context(), auditFrom(r, "REQUEST_CHANGE", "CHANGE_REQUEST", crid, nil, in))
	jsonResponse(w, 201, map[string]any{"id": crid, "status": "OPEN"})
}

func (s *Server) updateChangeRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var reviewID, assignee, requester, status string
	err := s.Store.Pool.QueryRow(r.Context(), `SELECT review_request_id,COALESCE(assignee_id,''),requester_id,status FROM change_requests WHERE id=$1`, id).Scan(&reviewID, &assignee, &requester, &status)
	if err != nil {
		problem(w, 404, "NOT_FOUND", "보완 요청을 찾을 수 없습니다.", nil)
		return
	}
	sess := session(r)
	if !s.canAccessReview(r.Context(), sess, reviewID) {
		problem(w, 404, "NOT_FOUND", "보완 요청을 찾을 수 없습니다.", nil)
		return
	}
	var in struct {
		Answer string `json:"answer"`
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Status == "DONE" {
		if sess.User.ID != assignee && !s.canEditReview(r.Context(), sess, reviewID) {
			problem(w, 403, "FORBIDDEN", "보완 조치를 완료할 권한이 없습니다.", nil)
			return
		}
	} else if in.Status == "VERIFIED" {
		if !s.canReview(r.Context(), sess, reviewID) {
			problem(w, 403, "FORBIDDEN", "보완 조치를 확인할 권한이 없습니다.", nil)
			return
		}
	} else {
		problem(w, 422, "VALIDATION_FAILED", "상태는 DONE 또는 VERIFIED여야 합니다.", nil)
		return
	}
	_, err = s.Store.Pool.Exec(r.Context(), `UPDATE change_requests SET answer=COALESCE(NULLIF($2,''),answer),status=$3,updated_at=now() WHERE id=$1`, id, in.Answer, in.Status)
	if err != nil {
		problem(w, 500, "UPDATE_FAILED", "보완 요청을 저장하지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPDATE_CHANGE_REQUEST", "CHANGE_REQUEST", id, map[string]string{"status": status}, in))
	if in.Status == "DONE" {
		s.addTargetedNotification(r.Context(), requester, "CHANGE_DONE", "보완 조치 완료", in.Answer, "REVIEW_REQUEST", reviewID)
	}
	jsonResponse(w, 200, map[string]string{"status": in.Status})
}

func (s *Server) completeReview(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.canReview(r.Context(), session(r), id) {
		problem(w, 403, "FORBIDDEN", "이 심의를 완료할 수 없습니다.", nil)
		return
	}
	var missing, open int
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id LEFT JOIN review_results rr ON rr.submission_item_id=si.id WHERE sub.review_request_id=$1 AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$1) AND (rr.id IS NULL OR rr.result='')`, id).Scan(&missing)
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM change_requests WHERE review_request_id=$1 AND status<>'VERIFIED'`, id).Scan(&open)
	if missing > 0 || open > 0 {
		problem(w, 422, "REVIEW_INCOMPLETE", "검토를 완료할 수 없습니다.", map[string]int{"unreviewed_items": missing, "unverified_changes": open})
		return
	}
	var in struct {
		FinalOpinion string `json:"final_opinion"`
		FinalResult  string `json:"final_result"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !contains([]string{"APPROVED", "CONDITIONAL", "REJECTED"}, in.FinalResult) || strings.TrimSpace(in.FinalOpinion) == "" {
		problem(w, 422, "VALIDATION_FAILED", "최종 결과와 최종 의견을 입력하세요.", nil)
		return
	}
	var wf struct {
		ApprovalEnabled bool `json:"approval_enabled"`
	}
	_, _ = s.Store.Setting(r.Context(), "workflow", &wf)
	next := "APPROVED"
	if in.FinalResult == "REJECTED" {
		next = "REJECTED"
	}
	if wf.ApprovalEnabled {
		next = "APPROVAL_PENDING"
	}
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE review_requests SET status=$2,final_opinion=$3,final_result=$4,approved_at=CASE WHEN $2='APPROVED' THEN now() ELSE NULL END,updated_at=now() WHERE id=$1 AND status='REVIEWING'`, id, next, in.FinalOpinion, in.FinalResult)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 500, "UPDATE_FAILED", "검토를 완료하지 못했습니다.", nil)
		return
	}
	event := "APPROVE"
	if next == "APPROVAL_PENDING" {
		event = "REQUEST_APPROVAL"
		var approver string
		_ = s.Store.Pool.QueryRow(r.Context(), `SELECT COALESCE(approver_id,'') FROM review_requests WHERE id=$1`, id).Scan(&approver)
		if approver != "" {
			s.addTargetedNotification(r.Context(), approver, "APPROVAL_PENDING", "최종 승인 요청", in.FinalOpinion, "REVIEW_REQUEST", id)
		}
	} else {
		var requester string
		_ = s.Store.Pool.QueryRow(r.Context(), `SELECT requester_id FROM review_requests WHERE id=$1`, id).Scan(&requester)
		s.addTargetedNotification(r.Context(), requester, "APPROVED", "심의 검토 완료", in.FinalOpinion, "REVIEW_REQUEST", id)
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, event, "REVIEW_REQUEST", id, nil, map[string]any{"status": next, "result": in.FinalResult}))
	jsonResponse(w, 200, map[string]string{"status": next})
}

func (s *Server) approveReview(w http.ResponseWriter, r *http.Request) {
	s.decideApproval(w, r, "APPROVED")
}
func (s *Server) rejectReview(w http.ResponseWriter, r *http.Request) {
	s.decideApproval(w, r, "REJECTED")
}

func (s *Server) cancelReview(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE review_requests SET status='CANCELLED',updated_at=now() WHERE id=$1 AND requester_id=$2 AND status IN ('DRAFT','CHANGE_REQUESTED')`, id, session(r).User.ID)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "STATE_CONFLICT", "작성 중이거나 보완 중인 본인 심의만 취소할 수 있습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "CANCEL", "REVIEW_REQUEST", id, nil, map[string]string{"status": "CANCELLED"}))
	jsonResponse(w, 200, map[string]string{"status": "CANCELLED"})
}

func (s *Server) closeReview(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE review_requests SET status='CLOSED',updated_at=now() WHERE id=$1 AND reviewer_id=$2 AND status IN ('APPROVED','REJECTED')`, id, session(r).User.ID)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "STATE_CONFLICT", "담당 검토자가 완료 또는 반려된 심의만 종료할 수 있습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "CLOSE", "REVIEW_REQUEST", id, nil, map[string]string{"status": "CLOSED"}))
	jsonResponse(w, 200, map[string]string{"status": "CLOSED"})
}

func (s *Server) decideApproval(w http.ResponseWriter, r *http.Request, decision string) {
	id := r.PathValue("id")
	var in struct{ Comment string }
	if !decodeJSON(w, r, &in) {
		return
	}
	sess := session(r)
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE review_requests SET status=$2,final_result=CASE WHEN $2='REJECTED' THEN 'REJECTED' ELSE final_result END,approved_at=CASE WHEN $2='APPROVED' THEN now() ELSE approved_at END,updated_at=now() WHERE id=$1 AND status='APPROVAL_PENDING' AND approver_id=$3`, id, decision, sess.User.ID)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "STATE_CONFLICT", "승인 처리할 수 없습니다.", nil)
		return
	}
	_, _ = s.Store.Pool.Exec(r.Context(), `INSERT INTO approvals(id,review_request_id,approver_id,decision,comment) VALUES($1,$2,$3,$4,$5)`, store.NewID(), id, sess.User.ID, decision, in.Comment)
	var requester string
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT requester_id FROM review_requests WHERE id=$1`, id).Scan(&requester)
	decisionTitle := map[string]string{"APPROVED": "심의 최종 승인", "REJECTED": "심의 반려"}[decision]
	s.addTargetedNotification(r.Context(), requester, decision, decisionTitle, in.Comment, "REVIEW_REQUEST", id)
	event := "APPROVE"
	if decision == "REJECTED" {
		event = "REJECT"
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, event, "REVIEW_REQUEST", id, nil, map[string]string{"decision": decision, "comment": in.Comment}))
	jsonResponse(w, 200, map[string]string{"status": decision})
}

func (s *Server) addParticipant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.canEditReview(r.Context(), session(r), id) {
		problem(w, 403, "FORBIDDEN", "공동 작성자를 지정할 수 없습니다.", nil)
		return
	}
	var in struct {
		UserID string `json:"user_id"`
		// Role decides whether the person can fill the checklist in or only
		// read it. Everyone used to get write access.
		Role string `json:"role"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Role == "" {
		in.Role = "CONTRIBUTOR"
	}
	if in.Role != "CONTRIBUTOR" && in.Role != "VIEWER" {
		problem(w, 422, "VALIDATION_FAILED", "참여 역할은 CONTRIBUTOR 또는 VIEWER여야 합니다.", nil)
		return
	}
	_, err := s.Store.Pool.Exec(r.Context(), `INSERT INTO review_participants(review_request_id,user_id,participant_role) VALUES($1,$2,$3)
                ON CONFLICT(review_request_id,user_id) DO UPDATE SET participant_role=EXCLUDED.participant_role`, id, in.UserID, in.Role)
	if err != nil {
		problem(w, 500, "UPDATE_FAILED", "공동 작성자를 지정하지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "ADD_PARTICIPANT", "REVIEW_REQUEST", id, nil, in))
	w.WriteHeader(204)
}

func (s *Server) listRuleCandidates(w http.ResponseWriter, r *http.Request) {
	reviewID := r.PathValue("id")
	var status string
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT status FROM review_requests WHERE id=$1`, reviewID).Scan(&status); err != nil {
		problem(w, 404, "NOT_FOUND", "심의를 찾을 수 없습니다.", nil)
		return
	}
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT i.id,t.name,v.version,i.item_code,COALESCE(sec.name,''),i.category,i.title,i.question,i.severity,COALESCE((SELECT si.id FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id WHERE sub.review_request_id=$1 AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$1) AND si.source_item_id=i.id LIMIT 1),'') AS assigned_item_id FROM checklist_items i JOIN checklist_versions v ON v.id=i.version_id JOIN checklist_templates t ON t.id=v.template_id LEFT JOIN checklist_sections sec ON sec.id=i.section_id WHERE t.active AND v.status='PUBLISHED' AND v.id=(SELECT v2.id FROM checklist_versions v2 WHERE v2.template_id=t.id AND v2.status='PUBLISHED' ORDER BY v2.published_at DESC NULLS LAST,v2.created_at DESC LIMIT 1) ORDER BY t.name,i.sort_order`, reviewID)
	if err != nil {
		problem(w, 500, "QUERY_FAILED", "Rule 후보를 불러오지 못했습니다.", nil)
		return
	}
	jsonResponse(w, 200, map[string]any{"editable": status == "DRAFT", "items": scanDynamic(rows, []string{"source_item_id", "template_name", "template_version", "item_code", "section", "category", "title", "question", "severity", "assigned_item_id"})})
}

func (s *Server) overrideRuleResult(w http.ResponseWriter, r *http.Request) {
	reviewID := r.PathValue("id")
	var in struct {
		Action       string `json:"action"`
		ItemID       string `json:"item_id"`
		SourceItemID string `json:"source_item_id"`
		Reason       string `json:"reason"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Action = strings.ToUpper(strings.TrimSpace(in.Action))
	in.Reason = strings.TrimSpace(in.Reason)
	if !contains([]string{"INCLUDE", "EXCLUDE"}, in.Action) || in.Reason == "" || len([]rune(in.Reason)) > 2000 {
		problem(w, 422, "VALIDATION_FAILED", "INCLUDE/EXCLUDE 작업과 1~2000자의 수동 변경 사유가 필요합니다.", nil)
		return
	}
	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		problem(w, 500, "UPDATE_FAILED", "Rule 결과를 변경하지 못했습니다.", nil)
		return
	}
	defer tx.Rollback(r.Context())
	var submissionID, status string
	err = tx.QueryRow(r.Context(), `SELECT sub.id,r.status FROM review_requests r JOIN submissions sub ON sub.review_request_id=r.id WHERE r.id=$1 ORDER BY sub.revision DESC LIMIT 1 FOR UPDATE OF r`, reviewID).Scan(&submissionID, &status)
	if err != nil {
		problem(w, 404, "NOT_FOUND", "심의를 찾을 수 없습니다.", nil)
		return
	}
	if status != "DRAFT" {
		problem(w, 409, "STATE_CONFLICT", "자동 배정 결과는 최초 제출 전 DRAFT 상태에서만 변경할 수 있습니다.", nil)
		return
	}
	sourceID := in.SourceItemID
	if in.Action == "EXCLUDE" {
		var used bool
		err = tx.QueryRow(r.Context(), `SELECT si.source_item_id,EXISTS(SELECT 1 FROM responses resp WHERE resp.submission_item_id=si.id) OR EXISTS(SELECT 1 FROM evidences e WHERE e.submission_item_id=si.id) FROM submission_items si WHERE si.id=$1 AND si.submission_id=$2`, in.ItemID, submissionID).Scan(&sourceID, &used)
		if err != nil {
			problem(w, 404, "NOT_FOUND", "제외할 배정 항목을 찾을 수 없습니다.", nil)
			return
		}
		if used {
			problem(w, 409, "ITEM_ALREADY_USED", "답변 또는 증적이 있는 항목은 제외할 수 없습니다.", nil)
			return
		}
		_, err = tx.Exec(r.Context(), `DELETE FROM submission_items WHERE id=$1 AND submission_id=$2`, in.ItemID, submissionID)
	} else {
		if sourceID == "" {
			problem(w, 422, "VALIDATION_FAILED", "포함할 원본 항목을 선택하세요.", nil)
			return
		}
		tag, insertErr := tx.Exec(r.Context(), `INSERT INTO submission_items(id,submission_id,source_item_id,template_name,template_version,item_code,section,category,title,question,guide,legal_basis,example,severity,required,answer_type,evidence_required,options_json,sort_order) SELECT $1,$2,i.id,t.name,v.version,i.item_code,COALESCE(sec.name,''),i.category,i.title,i.question,i.guide,i.legal_basis,i.example,i.severity,i.required,i.answer_type,i.evidence_required,i.options_json,i.sort_order FROM checklist_items i JOIN checklist_versions v ON v.id=i.version_id JOIN checklist_templates t ON t.id=v.template_id LEFT JOIN checklist_sections sec ON sec.id=i.section_id WHERE i.id=$3 AND t.active AND v.status='PUBLISHED' ON CONFLICT(submission_id,source_item_id) DO NOTHING`, store.NewID(), submissionID, sourceID)
		err = insertErr
		if err == nil && tag.RowsAffected() == 0 {
			problem(w, 409, "ALREADY_ASSIGNED", "이미 배정되었거나 게시 상태가 아닌 항목입니다.", nil)
			return
		}
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO rule_overrides(id,review_request_id,submission_id,source_item_id,action,reason,changed_by) VALUES($1,$2,$3,$4,$5,$6,$7)`, store.NewID(), reviewID, submissionID, sourceID, in.Action, in.Reason, session(r).User.ID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE review_requests SET manual_rule_override_reason=$2,updated_at=now() WHERE id=$1`, reviewID, in.Reason)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		problem(w, 500, "UPDATE_FAILED", "Rule 결과를 변경하지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "OVERRIDE_RULE", "REVIEW_REQUEST", reviewID, nil, map[string]any{"action": in.Action, "source_item_id": sourceID, "reason": in.Reason}))
	jsonResponse(w, 200, map[string]any{"action": in.Action, "source_item_id": sourceID})
}

func (s *Server) copyReview(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("id")
	sess := session(r)
	if !s.canAccessReview(r.Context(), sess, source) {
		problem(w, 404, "NOT_FOUND", "원본 심의를 찾을 수 없습니다.", nil)
		return
	}
	var in reviewInput
	err := s.Store.Pool.QueryRow(r.Context(), `SELECT service_name,description,service_type,'REVIEW',builder_id,developer_id,COALESCE(operator_id,''),department,COALESCE(reviewer_id,''),COALESCE(approver_id,''),NULL,exposure,has_admin_page,processes_personal_data,processes_credit_data,external_customer_service,uses_cloud,uses_docker,uses_kubernetes,external_integration,internet_access,business_criticality,'' FROM review_requests WHERE id=$1`, source).Scan(&in.ServiceName, &in.Description, &in.ServiceType, &in.ChangeType, &in.BuilderID, &in.DeveloperID, &in.OperatorID, &in.Department, &in.ReviewerID, &in.ApproverID, &in.PlannedOpenDate, &in.Exposure, &in.HasAdminPage, &in.ProcessesPersonalData, &in.ProcessesCreditData, &in.ExternalCustomerService, &in.UsesCloud, &in.UsesDocker, &in.UsesKubernetes, &in.ExternalIntegration, &in.InternetAccess, &in.BusinessCriticality, &in.ManualRuleOverrideReason)
	if err != nil {
		problem(w, 404, "NOT_FOUND", "원본 심의를 찾을 수 없습니다.", nil)
		return
	}
	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		problem(w, 500, "COPY_FAILED", "심의를 복사하지 못했습니다.", nil)
		return
	}
	defer tx.Rollback(r.Context())
	number, err := s.nextReviewNumber(r, tx)
	if err != nil {
		problem(w, 500, "COPY_FAILED", "심의번호를 발번하지 못했습니다.", nil)
		return
	}
	id, submissionID := store.NewID(), store.NewID()
	_, err = tx.Exec(r.Context(), `INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,operator_id,department,requester_id,reviewer_id,approver_id,exposure,has_admin_page,processes_personal_data,processes_credit_data,external_customer_service,uses_cloud,uses_docker,uses_kubernetes,external_integration,internet_access,business_criticality) VALUES($1,$2,$3,$4,$5,'REVIEW',$6,$7,NULLIF($8,''),$9,$10,NULLIF($11,''),NULLIF($12,''),$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`, id, number, in.ServiceName, in.Description, in.ServiceType, in.BuilderID, in.DeveloperID, in.OperatorID, in.Department, sess.User.ID, in.ReviewerID, in.ApproverID, in.Exposure, in.HasAdminPage, in.ProcessesPersonalData, in.ProcessesCreditData, in.ExternalCustomerService, in.UsesCloud, in.UsesDocker, in.UsesKubernetes, in.ExternalIntegration, in.InternetAccess, in.BusinessCriticality)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO submissions(id,review_request_id) VALUES($1,$2)`, submissionID, id)
	}
	if err == nil {
		_, err = s.snapshotApplicableItems(r.Context(), tx, submissionID, in)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO responses(id,submission_item_id,answer_json,applicability,self_assessment,current_state,na_reason,action_plan,assigned_to,updated_by) SELECT gen_random_uuid()::text,new_item.id,old_resp.answer_json,old_resp.applicability,old_resp.self_assessment,old_resp.current_state,old_resp.na_reason,old_resp.action_plan,NULL,$1 FROM submissions old_sub JOIN submission_items old_item ON old_item.submission_id=old_sub.id JOIN responses old_resp ON old_resp.submission_item_id=old_item.id JOIN submission_items new_item ON new_item.submission_id=$2 AND new_item.template_name=old_item.template_name AND new_item.item_code=old_item.item_code WHERE old_sub.review_request_id=$3 AND old_sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$3)`, sess.User.ID, submissionID, source)
	}
	// A re-review is assigned from today's published templates, so some items
	// are new and some no longer exist. Saying nothing left the requester to
	// discover that by scrolling.
	var carried, total, added, dropped int
	if err == nil {
		err = tx.QueryRow(r.Context(), `SELECT
                  (SELECT count(*) FROM submission_items si JOIN responses resp ON resp.submission_item_id=si.id WHERE si.submission_id=$1 AND resp.applicability<>''),
                  (SELECT count(*) FROM submission_items si WHERE si.submission_id=$1),
                  (SELECT count(*) FROM submission_items new_item WHERE new_item.submission_id=$1 AND NOT EXISTS(
                     SELECT 1 FROM submissions old_sub JOIN submission_items old_item ON old_item.submission_id=old_sub.id
                     WHERE old_sub.review_request_id=$2 AND old_sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$2)
                       AND old_item.template_name=new_item.template_name AND old_item.item_code=new_item.item_code)),
                  (SELECT count(*) FROM submissions old_sub JOIN submission_items old_item ON old_item.submission_id=old_sub.id
                     WHERE old_sub.review_request_id=$2 AND old_sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$2)
                       AND NOT EXISTS(SELECT 1 FROM submission_items new_item WHERE new_item.submission_id=$1 AND new_item.template_name=old_item.template_name AND new_item.item_code=old_item.item_code))`,
			submissionID, source).Scan(&carried, &total, &added, &dropped)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		problem(w, 500, "COPY_FAILED", "심의를 복사하지 못했습니다.", err.Error())
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "COPY_SUBMISSION", "REVIEW_REQUEST", id, map[string]string{"source": source}, map[string]any{"review_number": number, "carried": carried, "new_items": added, "dropped_items": dropped}))
	jsonResponse(w, 201, map[string]any{"id": id, "review_number": number, "carried": carried, "total": total, "new_items": added, "dropped_items": dropped})
}

// canAccessReviewAs answers the same question for a user id rather than the
// caller's own session, which is what assignment needs: you may only hand an
// item to someone who can already open the review.
func (s *Server) canAccessReviewAs(ctx context.Context, userID, reviewID string) bool {
	var ok bool
	_ = s.Store.Pool.QueryRow(ctx, `SELECT EXISTS(
                SELECT 1 FROM review_requests r WHERE r.id=$1 AND (
                  r.requester_id=$2 OR r.builder_id=$2 OR r.developer_id=$2 OR r.operator_id=$2 OR r.reviewer_id=$2 OR r.approver_id=$2
                  OR EXISTS(SELECT 1 FROM review_participants p WHERE p.review_request_id=r.id AND p.user_id=$2 AND p.participant_role='CONTRIBUTOR')))`, reviewID, userID).Scan(&ok)
	return ok
}

func (s *Server) canAccessReview(ctx context.Context, sess auth.Session, id string) bool {
	if hasAnyRole(sess.User, "SECURITY_REVIEWER", "AUDITOR") {
		var ok bool
		_ = s.Store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM review_requests WHERE id=$1)`, id).Scan(&ok)
		return ok
	}
	var ok bool
	_ = s.Store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM review_requests r WHERE r.id=$1 AND (r.requester_id=$2 OR r.builder_id=$2 OR r.developer_id=$2 OR r.reviewer_id=$2 OR r.approver_id=$2 OR EXISTS(SELECT 1 FROM review_participants p WHERE p.review_request_id=r.id AND p.user_id=$2)))`, id, sess.User.ID).Scan(&ok)
	return ok
}
func (s *Server) canEditReview(ctx context.Context, sess auth.Session, id string) bool {
	var ok bool
	_ = s.Store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM review_requests r WHERE r.id=$1 AND r.status IN ('DRAFT','CHANGE_REQUESTED') AND (r.requester_id=$2 OR r.builder_id=$2 OR r.developer_id=$2 OR EXISTS(SELECT 1 FROM review_participants p WHERE p.review_request_id=r.id AND p.user_id=$2 AND p.participant_role='CONTRIBUTOR')))`, id, sess.User.ID).Scan(&ok)
	return ok
}
func (s *Server) canReview(ctx context.Context, sess auth.Session, id string) bool {
	if !containsRole(sess.User, "SECURITY_REVIEWER") {
		return false
	}
	var ok bool
	_ = s.Store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM review_requests WHERE id=$1 AND reviewer_id=$2)`, id, sess.User.ID).Scan(&ok)
	return ok
}

// addNotification records an in-app notification and decides whether it also
// leaves as e-mail. In-app delivery is unconditional: the notification centre
// is the record of what happened. E-mail obeys the global switch and then the
// recipient's own preferences, so nobody is forced to receive every event.
func (s *Server) addNotification(ctx context.Context, recipient, event, title, body string) {
	s.addTargetedNotification(ctx, recipient, event, title, body, "", "")
}

func (s *Server) addTargetedNotification(ctx context.Context, recipient, event, title, body, targetType, targetID string) {
	if recipient == "" {
		return
	}
	id := store.NewID()
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO notifications(id,recipient_id,event_type,title,body,target_type,target_id) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, recipient, event, title, body, targetType, targetID)
	if err == nil && s.emailWanted(ctx, tx, recipient, event) {
		_, err = tx.Exec(ctx, `INSERT INTO jobs(id,type,payload) VALUES($1,'SEND_EMAIL',jsonb_build_object('notification_id',$2::text))`, store.NewID(), id)
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE notifications SET emailed_at=now() WHERE id=$1`, id)
		}
	}
	// A swallowed failure here used to roll the whole notification away in
	// silence, so the error is recorded even though delivery is best-effort.
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		s.Store.Log(ctx, "ERROR", "", "notification", "notification could not be recorded", map[string]any{"error": err.Error(), "event": event, "recipient": recipient})
	}
}

// emailWanted answers whether this event should be queued for immediate
// e-mail. A daily-digest recipient is left alone here; the digest worker picks
// the notification up later because emailed_at stays null.
func (s *Server) emailWanted(ctx context.Context, tx pgx.Tx, recipient, event string) bool {
	var cfg struct {
		EmailEnabled bool `json:"email_enabled"`
	}
	if _, err := s.Store.Setting(ctx, "notification", &cfg); err != nil || !cfg.EmailEnabled {
		return false
	}
	var enabled bool
	var digest string
	var muted []string
	err := tx.QueryRow(ctx, `SELECT email_enabled,digest,muted_events FROM notification_preferences WHERE user_id=$1`, recipient).Scan(&enabled, &digest, &muted)
	if errors.Is(err, pgx.ErrNoRows) {
		// No preference recorded means the default: everything, immediately.
		return true
	}
	if err != nil || !enabled || contains(muted, event) {
		return false
	}
	return digest != "DAILY"
}

func (s *Server) notifyReviewer(ctx context.Context, id, event, body string) {
	var recipient, number, service string
	_ = s.Store.Pool.QueryRow(ctx, `SELECT COALESCE(reviewer_id,''),review_number,service_name FROM review_requests WHERE id=$1`, id).Scan(&recipient, &number, &service)
	if recipient == "" {
		return
	}
	if body == "" {
		// The message used to quote the internal UUID, which means nothing to
		// the person reading it.
		body = fmt.Sprintf("%s(%s) 심의가 제출되었습니다. 검토를 시작하세요.", number, service)
	}
	s.addTargetedNotification(ctx, recipient, event, "새 심의 제출", body, "REVIEW_REQUEST", id)
}

var _ = errors.Is
