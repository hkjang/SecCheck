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
		add("review_requests.created_at >= display_day_start($%d::date)", v)
	}
	if v := strings.TrimSpace(query.Get("to")); v != "" {
		add("review_requests.created_at < display_day_start($%d::date + 1)", v)
	}
	// The launch happens on its date whether or not the review is finished, so
	// "which of these will open unreviewed" is a queue somebody has to work.
	if strings.TrimSpace(query.Get("open_at_risk")) == "1" {
		where += " AND review_requests.planned_open_date IS NOT NULL AND review_requests.planned_open_date <= display_today()+14" +
			" AND review_requests.status NOT IN ('APPROVED','CLOSED','CANCELLED','REJECTED')"
	}
	if strings.TrimSpace(query.Get("overdue")) == "1" {
		where += " AND EXISTS(SELECT 1 FROM change_requests oc WHERE oc.review_request_id=review_requests.id AND oc.status<>'VERIFIED' AND oc.due_date < display_today())"
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
        (SELECT count(*) FROM change_requests c WHERE c.review_request_id=review_requests.id AND c.status<>'VERIFIED' AND c.due_date < display_today()),
        review_requests.created_at,review_requests.updated_at
        FROM review_requests JOIN users requester ON requester.id=review_requests.requester_id LEFT JOIN users reviewer ON reviewer.id=review_requests.reviewer_id WHERE `

func (s *Server) listReviewRequests(w http.ResponseWriter, r *http.Request) {
	where, args := s.reviewFilter(r)
	order := reviewSorts["updated"]
	if v := reviewSorts[strings.TrimSpace(r.URL.Query().Get("sort"))]; v != "" {
		order = v
	}
	if r.URL.Query().Get("format") == "csv" {
		rows, err := s.Store.Pool.Query(r.Context(), reviewSelect+where+` ORDER BY `+order+` LIMIT `+intString(exportRowCap+1), args...)
		if err != nil {
			s.fault(w, r, "QUERY_FAILED", "심의 목록을 불러오지 못했습니다.", err)
			return
		}
		listed, scanErr := scanDynamic(rows, reviewColumns)
		if scanErr != nil {
			s.fault(w, r, "QUERY_FAILED", "심의 목록을 불러오지 못했습니다.", scanErr)
			return
		}
		records, truncated := capExport(w, listed)
		_ = s.Store.Audit(r.Context(), auditFrom(r, "EXPORT_REVIEW_LIST", "REVIEW_REQUEST", "", nil, map[string]any{"rows": len(records), "truncated": truncated}))
		writeCSV(w, "seccheck-reviews", s.Store.Location(r.Context()), reviewColumns, records)
		return
	}

	limit, offset := parsePage(r)
	var total int64
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM review_requests WHERE `+where, args...).Scan(&total); err != nil {
		s.fault(w, r, "QUERY_FAILED", "심의 목록을 불러오지 못했습니다.", err)
		return
	}
	paged := append(append([]any{}, args...), limit, offset)
	rows, err := s.Store.Pool.Query(r.Context(), reviewSelect+where+fmt.Sprintf(` ORDER BY %s LIMIT $%d OFFSET $%d`, order, len(args)+1, len(args)+2), paged...)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "심의 목록을 불러오지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, reviewColumns)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "심의 목록을 불러오지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset, "has_more": int64(offset+len(items)) < total})
}

// stillHolds reports, in SQL, whether the named column points at somebody who
// can still do the job the review is waiting on: an open account that still
// holds the role. Losing the role -- a transfer, a leaver, a mistaken edit --
// otherwise leaves the review pinned to a person who is refused every action on
// it, and pinned means invisible in every other reviewer's queue. Nobody is
// stopped, so nobody notices; the review simply stops moving.
func stillHolds(column, role string) string {
	return fmt.Sprintf(`EXISTS(SELECT 1 FROM user_roles ur JOIN users u ON u.id=ur.user_id WHERE ur.user_id=%s AND ur.role_code='%s' AND u.active)`, column, role)
}

// myTurnClause selects the reviews that are waiting on this specific person,
// which is what the dashboard queue and the "내 차례" filter both mean.
func myTurnClause(sess auth.Session, n int) string {
	var branches []string
	branches = append(branches, fmt.Sprintf(`(review_requests.status IN ('DRAFT','CHANGE_REQUESTED') AND (review_requests.requester_id=$%[1]d OR review_requests.builder_id=$%[1]d OR review_requests.developer_id=$%[1]d OR review_requests.operator_id=$%[1]d OR EXISTS(SELECT 1 FROM review_participants rp WHERE rp.review_request_id=review_requests.id AND rp.user_id=$%[1]d AND rp.participant_role='CONTRIBUTOR')))`, n))
	if hasAnyRole(sess.User, "SECURITY_REVIEWER") {
		orphaned := "NOT " + stillHolds("review_requests.reviewer_id", "SECURITY_REVIEWER")
		branches = append(branches, fmt.Sprintf(`(review_requests.status IN ('SUBMITTED','RESUBMITTED') AND (review_requests.reviewer_id IS NULL OR review_requests.reviewer_id=$%d OR %s))`, n, orphaned))
		branches = append(branches, fmt.Sprintf(`(review_requests.status='REVIEWING' AND (review_requests.reviewer_id=$%d OR %s))`, n, orphaned))
	}
	if hasAnyRole(sess.User, "APPROVER") {
		branches = append(branches, fmt.Sprintf(`(review_requests.status='APPROVAL_PENDING' AND (review_requests.approver_id IS NULL OR review_requests.approver_id=$%d OR NOT %s))`, n, stillHolds("review_requests.approver_id", "APPROVER")))
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

// A field that only has to be non-empty can be two megabytes long, and the
// service name in particular is copied into every notification about the
// review -- one long name becomes a mailbox full of them.
var reviewFieldLimits = map[string]int{"service_name": 200, "department": 100, "description": longTextLimit}

func validateReviewInput(in reviewInput) map[string]string {
	e := map[string]string{}
	for key, limit := range reviewFieldLimits {
		value := map[string]string{"service_name": in.ServiceName, "department": in.Department, "description": in.Description}[key]
		if len([]rune(value)) > limit {
			e[key] = fmt.Sprintf("%d자 이내로 입력하세요.", limit)
		}
	}
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
		s.fault(w, r, "CREATE_FAILED", "심의를 생성하지 못했습니다.", err)
		return
	}
	defer tx.Rollback(r.Context())
	number, err := s.nextReviewNumber(r, tx)
	if err != nil {
		s.fault(w, r, "CREATE_FAILED", "심의번호를 발번하지 못했습니다.", err)
		return
	}
	id, submissionID := store.NewID(), store.NewID()
	_, err = tx.Exec(r.Context(), `INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,operator_id,department,requester_id,reviewer_id,approver_id,planned_open_date,exposure,has_admin_page,processes_personal_data,processes_credit_data,external_customer_service,uses_cloud,uses_docker,uses_kubernetes,external_integration,internet_access,business_criticality,manual_rule_override_reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),$10,$11,NULLIF($12,''),NULLIF($13,''),NULLIF($14,'')::date,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)`, id, number, in.ServiceName, in.Description, in.ServiceType, in.ChangeType, in.BuilderID, in.DeveloperID, in.OperatorID, in.Department, sess.User.ID, in.ReviewerID, in.ApproverID, dateValue(in.PlannedOpenDate), in.Exposure, in.HasAdminPage, in.ProcessesPersonalData, in.ProcessesCreditData, in.ExternalCustomerService, in.UsesCloud, in.UsesDocker, in.UsesKubernetes, in.ExternalIntegration, in.InternetAccess, in.BusinessCriticality, in.ManualRuleOverrideReason)
	if err != nil {
		s.fault(w, r, "CREATE_FAILED", "심의를 생성하지 못했습니다.", err)
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO submissions(id,review_request_id) VALUES($1,$2)`, submissionID, id)
	if err != nil {
		s.fault(w, r, "CREATE_FAILED", "제출본을 생성하지 못했습니다.", err)
		return
	}
	n, err := s.snapshotApplicableItems(r.Context(), tx, submissionID, in)
	if err != nil {
		s.fault(w, r, "SNAPSHOT_FAILED", "체크리스트를 배정하지 못했습니다.", err)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		s.fault(w, r, "CREATE_FAILED", "심의를 생성하지 못했습니다.", err)
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

// A rule that names a field the review form does not have can never match, so
// the item it guards quietly stops appearing in reviews: a security
// requirement that is never assessed and nobody is told about. The vocabulary
// is taken from reviewFields itself, so it cannot drift from what the engine
// actually evaluates.
func ruleVocabulary() map[string]bool {
	known := map[string]bool{}
	for name := range reviewFields(reviewInput{}) {
		known[name] = true
	}
	return known
}

var ruleOperators = map[string]bool{"": true, "eq": true, "=": true, "neq": true, "!=": true, "in": true, "contains": true, "gt": true, "gte": true, "lt": true, "lte": true, "exists": true}

// validateRule reports the first thing in a rule that the engine could never
// act on, in a form an administrator can correct.
func validateRule(node any, known map[string]bool) error {
	m, ok := node.(map[string]any)
	if !ok {
		return errors.New("조건은 객체여야 합니다")
	}
	for _, key := range []string{"all", "any"} {
		if group, exists := m[key]; exists {
			list, isList := group.([]any)
			if !isList || len(list) == 0 {
				return fmt.Errorf("%s 조건에는 하나 이상의 하위 조건이 필요합니다", key)
			}
			for _, child := range list {
				if err := validateRule(child, known); err != nil {
					return err
				}
			}
			return nil
		}
	}
	if not, exists := m["not"]; exists {
		return validateRule(not, known)
	}
	field, _ := m["field"].(string)
	if field == "" {
		return errors.New("조건에 field가 없습니다")
	}
	if !known[field] {
		return fmt.Errorf("알 수 없는 항목입니다: %s", field)
	}
	op, _ := m["operator"].(string)
	if !ruleOperators[strings.ToLower(op)] {
		return fmt.Errorf("알 수 없는 연산자입니다: %s", op)
	}
	if strings.EqualFold(op, "in") {
		if values, isList := m["value"].([]any); !isList || len(values) == 0 {
			return errors.New("in 연산자에는 값 목록이 필요합니다")
		}
	}
	return nil
}

// checkedRule validates what a caller sent for an item, if anything.
func checkedRule(rule any) error {
	if rule == nil {
		return nil
	}
	if m, ok := rule.(map[string]any); ok && len(m) == 0 {
		return nil
	}
	return validateRule(rule, ruleVocabulary())
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
	row := s.Store.Pool.QueryRow(r.Context(), `SELECT to_jsonb(r)-'description'||jsonb_build_object('description',r.description,'requester_name',ru.display_name,'reviewer_name',rv.display_name,'approver_name',ap.display_name,'decisions',(SELECT COALESCE(jsonb_agg(jsonb_build_object('decision',a.decision,'comment',a.comment,'decided_at',a.created_at,'approver_name',au.display_name) ORDER BY a.created_at),'[]') FROM approvals a JOIN users au ON au.id=a.approver_id WHERE a.review_request_id=r.id),'progress',(SELECT jsonb_build_object('total',count(*),'answered',count(resp.id),'evidence',count(DISTINCT ev.id)) FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id LEFT JOIN responses resp ON resp.submission_item_id=si.id LEFT JOIN evidences ev ON ev.submission_item_id=si.id AND ev.deleted_at IS NULL WHERE sub.review_request_id=r.id AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=r.id)),'risk_score',(SELECT COALESCE(sum(CASE si.severity WHEN 'CRITICAL' THEN 10 WHEN 'HIGH' THEN 7 WHEN 'MEDIUM' THEN 3 ELSE 1 END) FILTER(WHERE rr.result IN ('INSUFFICIENT','NON_COMPLIANT','CONDITIONAL','RECHECK')),0) FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id LEFT JOIN review_results rr ON rr.submission_item_id=si.id WHERE sub.review_request_id=r.id AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=r.id))) FROM review_requests r JOIN users ru ON ru.id=r.requester_id LEFT JOIN users rv ON rv.id=r.reviewer_id LEFT JOIN users ap ON ap.id=r.approver_id WHERE r.id=$1`, r.PathValue("id"))
	var data []byte
	if err := row.Scan(&data); err != nil {
		problem(w, 404, "NOT_FOUND", "심의를 찾을 수 없습니다.", nil)
		return
	}
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	var total, compliant, conditional, insufficient, nonCompliant, na, followUp, staleVerdicts int
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*),count(*) FILTER(WHERE rr.result='COMPLIANT'),count(*) FILTER(WHERE rr.result='CONDITIONAL'),count(*) FILTER(WHERE rr.result='INSUFFICIENT'),count(*) FILTER(WHERE rr.result='NON_COMPLIANT'),count(*) FILTER(WHERE rr.result='NA_ACCEPTED' OR resp.applicability='N/A'),count(*) FILTER(WHERE COALESCE(rr.follow_up,'')<>''),count(*) FILTER(WHERE `+staleVerdictSQL+`) FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id LEFT JOIN responses resp ON resp.submission_item_id=si.id LEFT JOIN review_results rr ON rr.submission_item_id=si.id WHERE sub.review_request_id=$1 AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$1)`, r.PathValue("id")).Scan(&total, &compliant, &conditional, &insufficient, &nonCompliant, &na, &followUp, &staleVerdicts)
	naRatio := 0.0
	if total > 0 {
		naRatio = float64(na) * 100 / float64(total)
	}
	out["result_summary"] = map[string]any{"total": total, "compliant": compliant, "conditional": conditional, "insufficient": insufficient, "non_compliant": nonCompliant, "na": na, "na_ratio": naRatio, "follow_up": followUp, "stale_verdicts": staleVerdicts}
	// The screen has to be able to say that the named reviewer or approver can
	// no longer act, because until somebody takes the review over it does not
	// move and nothing else says so.
	var reviewerCanAct, approverCanAct bool
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT `+stillHolds("reviewer_id", "SECURITY_REVIEWER")+`,`+stillHolds("approver_id", "APPROVER")+` FROM review_requests WHERE id=$1`, r.PathValue("id")).Scan(&reviewerCanAct, &approverCanAct)
	out["reviewer_can_act"] = reviewerCanAct
	out["approver_can_act"] = approverCanAct
	out["template_versions"] = s.snapshotTemplateVersions(r, r.PathValue("id"))
	_ = s.Store.Audit(r.Context(), auditFrom(r, "VIEW_SUBMISSION", "REVIEW_REQUEST", r.PathValue("id"), nil, nil))
	jsonResponse(w, 200, out)
}

func (s *Server) updateReviewRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
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
	if field := tooLong(map[string]string{"description": in.Description}, longTextLimit); field != "" {
		problem(w, 422, "VALIDATION_FAILED", fmt.Sprintf("설명은 %d자 이내로 입력하세요.", longTextLimit), map[string]string{field: "너무 깁니다."})
		return
	}
	if !s.canEditReview(r.Context(), session(r), id) {
		// A review waiting for approval is frozen and only its named approver
		// may decide it, so an approver who has left the organisation strands
		// it for good. Handing the approval to someone else is the way out,
		// and it is the only change an administrator may make at this stage.
		if in.ApproverID != "" && hasAnyRole(session(r).User, "SYSTEM_ADMIN") && s.reassignApprover(w, r, id, in.ApproverID) {
			return
		}
		problem(w, 403, "FORBIDDEN", "이 심의를 수정할 수 없습니다.", nil)
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

// reassignApprover moves a pending approval to another approver. It reports
// whether it applied, so the caller can fall through to the ordinary refusal
// when the review is not actually waiting for approval.
func (s *Server) reassignApprover(w http.ResponseWriter, r *http.Request, id, approverID string) bool {
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE review_requests SET approver_id=$2,updated_at=now()
                WHERE id=$1 AND status='APPROVAL_PENDING' AND EXISTS(SELECT 1 FROM user_roles ur WHERE ur.user_id=$2 AND ur.role_code='APPROVER')`, id, approverID)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "STATE_CONFLICT", "최종 승인 대기 중인 심의의 승인자만 변경할 수 있으며, 대상은 승인자 권한을 가져야 합니다.", nil)
		return true
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "REASSIGN_APPROVER", "REVIEW_REQUEST", id, nil, map[string]string{"approver_id": approverID}))
	s.addTargetedNotification(r.Context(), approverID, "APPROVAL_PENDING", "최종 승인 요청", "이전 승인자를 대신하여 최종 승인이 요청되었습니다.", "REVIEW_REQUEST", id)
	jsonResponse(w, 200, map[string]any{"id": id, "approver_id": approverID})
	return true
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
	out, scanErr := scanDynamic(rows, []string{"template_name", "snapshot_version", "current_version"})
	if scanErr != nil {
		return []map[string]any{}
	}
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
		s.fault(w, r, "QUERY_FAILED", "심의 이력을 불러오지 못했습니다.", err)
		return
	}
	// The entry's own identifier travels with it: without it a reader looking
	// at "누가 무엇을 했다" on this screen has no way to reach the full record
	// -- the before and after values -- in the audit log.
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT a.event_id,a.timestamp,a.event_type,a.user_name,a.target_type,a.target_id,a.result,
                COALESCE((SELECT si.item_code FROM submission_items si WHERE si.id=a.target_id),'') AS item_code
                FROM audit_logs a WHERE `+scope+` ORDER BY a.timestamp DESC,a.chain_sequence DESC LIMIT $2 OFFSET $3`, id, limit, offset)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "심의 이력을 불러오지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, []string{"event_id", "timestamp", "event_type", "user_name", "target_type", "target_id", "result", "item_code"})
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "이력을 불러오지 못했습니다.", err)
		return
	}
	for _, item := range items {
		if code, ok := item["event_type"].(string); ok {
			item["event_label"] = auditEventLabels[code]
		}
	}
	jsonResponse(w, 200, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset, "has_more": int64(offset+len(items)) < total})
}

// A verdict describes the answer and the evidence the reviewer had in front of
// them, and a change request hands the whole review back to the author, who can
// move either. Judged before the last edit means judged against something that
// is no longer there, so the completion guard, the summary and the item list
// all read staleness the same way.
const staleVerdictSQL = `COALESCE(rr.result,'')<>'' AND GREATEST(resp.updated_at,COALESCE(evidence_touched_at(si.id),resp.updated_at)) > rr.updated_at`

// staleVerdicts counts the items of a review whose verdict predates the answer
// or evidence it judged.
func (s *Server) staleVerdicts(ctx context.Context, id string) (int, error) {
	var count int
	err := s.Store.Pool.QueryRow(ctx, `SELECT count(*) FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id JOIN review_results rr ON rr.submission_item_id=si.id JOIN responses resp ON resp.submission_item_id=si.id WHERE sub.review_request_id=$1 AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$1) AND `+staleVerdictSQL, id).Scan(&count)
	return count, err
}

func (s *Server) listSubmissionItems(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.canAccessReview(r.Context(), session(r), id) {
		problem(w, 404, "NOT_FOUND", "심의를 찾을 수 없습니다.", nil)
		return
	}
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT si.id,si.template_name,si.template_version,si.item_code,si.section,si.category,si.title,si.question,si.guide,si.legal_basis,si.example,si.severity,si.required,si.answer_type,si.evidence_required,si.options_json,si.sort_order,COALESCE(to_jsonb(resp),'{}'),COALESCE(to_jsonb(rr),'{}'),COALESCE((SELECT jsonb_agg((to_jsonb(e)-'stored_filename')||jsonb_build_object('uploaded_by_name',eu.display_name) ORDER BY e.created_at) FROM evidences e JOIN users eu ON eu.id=e.uploaded_by WHERE e.submission_item_id=si.id AND e.deleted_at IS NULL),'[]'),COALESCE((SELECT jsonb_agg(to_jsonb(cr) ORDER BY cr.created_at) FROM change_requests cr WHERE cr.submission_item_id=si.id),'[]'),COALESCE((SELECT jsonb_agg(to_jsonb(c)||jsonb_build_object('author_name',u.display_name) ORDER BY c.created_at) FROM comments c JOIN users u ON u.id=c.author_id WHERE c.submission_item_id=si.id),'[]'),COALESCE(`+staleVerdictSQL+`,false) FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id LEFT JOIN responses resp ON resp.submission_item_id=si.id LEFT JOIN review_results rr ON rr.submission_item_id=si.id WHERE sub.review_request_id=$1 AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$1) ORDER BY si.template_name,si.sort_order`, id)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "체크리스트를 불러오지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, []string{"id", "template_name", "template_version", "item_code", "section", "category", "title", "question", "guide", "legal_basis", "example", "severity", "required", "answer_type", "evidence_required", "options", "sort_order", "response", "review_result", "evidences", "change_requests", "comments", "stale_verdict"})
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "목록을 불러오지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, items)
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
		s.fault(w, r, "CREATE_FAILED", "코멘트를 저장하지 못했습니다.", err)
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
	var number, service, requester, reviewer, builder, developer, operator string
	var assignee *string
	err := s.Store.Pool.QueryRow(r.Context(), `SELECT rq.review_number,rq.service_name,rq.requester_id,COALESCE(rq.reviewer_id,''),rq.builder_id,rq.developer_id,COALESCE(rq.operator_id,''),
                (SELECT resp.assigned_to FROM responses resp WHERE resp.submission_item_id=$2)
                FROM review_requests rq WHERE rq.id=$1`, reviewID, itemID).
		Scan(&number, &service, &requester, &reviewer, &builder, &developer, &operator, &assignee)
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
		recipients[operator] = true
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
	if field := tooLong(map[string]string{"current_state": in.CurrentState, "action_plan": in.ActionPlan, "na_reason": in.NAReason}, longTextLimit); field != "" {
		problem(w, 422, "VALIDATION_FAILED", fmt.Sprintf("입력이 너무 깁니다. %d자 이내로 작성하세요.", longTextLimit), map[string]string{field: fmt.Sprintf("%d자를 넘습니다.", longTextLimit)})
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
		s.fault(w, r, "VALIDATION_FAILED", "제출 검증에 실패했습니다.", err)
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
	// The submission carries who submitted and when, which the cycle-time
	// report measures from. It used to be written after the status had already
	// committed, with its error discarded, so a failure left a review marked
	// submitted whose submission still read DRAFT with no submitter.
	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		s.fault(w, r, "SUBMIT_FAILED", "심의를 제출하지 못했습니다.", err)
		return
	}
	defer tx.Rollback(r.Context())
	tag, err := tx.Exec(r.Context(), `UPDATE review_requests SET status=$2,first_submitted_at=COALESCE(first_submitted_at,now()),final_submitted_at=now(),updated_at=now() WHERE id=$1 AND status IN ('DRAFT','CHANGE_REQUESTED')`, id, next)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "STATE_CONFLICT", "현재 상태에서는 제출할 수 없습니다.", nil)
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE submissions SET status=$2,submitted_by=$3,submitted_at=now() WHERE review_request_id=$1 AND revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$1)`, id, next, session(r).User.ID); err != nil {
		s.fault(w, r, "SUBMIT_FAILED", "심의를 제출하지 못했습니다.", err)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		s.fault(w, r, "SUBMIT_FAILED", "심의를 제출하지 못했습니다.", err)
		return
	}
	// Coming back from a change request, the reviewer already judged this
	// checklist. What they need is not "start reviewing" but which of their own
	// verdicts no longer describes what is on the screen.
	if next == "RESUBMITTED" {
		notice := "심의가 재제출되었습니다. 검토를 이어서 진행하세요."
		if stale, err := s.staleVerdicts(r.Context(), id); err == nil && stale > 0 {
			notice = fmt.Sprintf("심의가 재제출되었습니다. 판정 이후 답변·증적이 바뀐 항목 %d건을 다시 확인하세요.", stale)
		}
		s.notifyReviewer(r.Context(), id, "REVIEW_SUBMITTED", "심의 재제출", notice)
	} else {
		s.notifyReviewer(r.Context(), id, "REVIEW_SUBMITTED", "", "")
	}
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
	// Taking your own request to review is the same conflict as approving it.
	if s.selfReviewBlocked(r.Context(), id, sess.User.ID) {
		problem(w, 403, "SELF_REVIEW_FORBIDDEN", "본인이 신청한 심의는 본인이 검토할 수 없습니다. 다른 검토자가 맡아야 합니다.", nil)
		return
	}
	// A review whose named reviewer can no longer act is free for the taking,
	// and taking it has to move the name too -- otherwise every later step
	// still asks the person who left.
	orphaned := "NOT " + stillHolds("reviewer_id", "SECURITY_REVIEWER")
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE review_requests SET status='REVIEWING',reviewer_id=CASE WHEN reviewer_id IS NULL OR `+orphaned+` THEN $2 ELSE reviewer_id END,updated_at=now() WHERE id=$1 AND ((status IN ('SUBMITTED','RESUBMITTED') AND (reviewer_id IS NULL OR reviewer_id=$2 OR `+orphaned+`)) OR (status='REVIEWING' AND `+orphaned+`))`, id, sess.User.ID)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "STATE_CONFLICT", "심의를 시작할 수 없습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "BEGIN_REVIEW", "REVIEW_REQUEST", id, nil, map[string]string{"status": "REVIEWING"}))
	jsonResponse(w, 200, map[string]string{"status": "REVIEWING"})
}

// bulkSaveReviewResults judges several items at once. The person filling a
// checklist in has had this since the beginning; the reviewer, who works
// through every one of the same items, had to open each in turn. Long runs of
// the same verdict are exactly what makes a review take an afternoon.
// reviewResults is the shared vocabulary of the single and bulk judgements,
// so the two cannot drift apart.
var reviewResults = map[string]bool{"COMPLIANT": true, "CONDITIONAL": true, "INSUFFICIENT": true, "NON_COMPLIANT": true, "NA_ACCEPTED": true, "RECHECK": true}

func (s *Server) bulkSaveReviewResults(w http.ResponseWriter, r *http.Request) {
	reviewID := r.PathValue("id")
	if !s.canReview(r.Context(), session(r), reviewID) {
		problem(w, 403, "FORBIDDEN", "이 심의를 검토할 수 없습니다.", nil)
		return
	}
	var in struct {
		ItemIDs            []string `json:"item_ids"`
		Result             string   `json:"result"`
		FinalApplicability string   `json:"final_applicability"`
		EvidenceAdequacy   string   `json:"evidence_adequacy"`
		Opinion            string   `json:"opinion"`
		Overwrite          bool     `json:"overwrite"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.ItemIDs) == 0 {
		problem(w, 422, "VALIDATION_FAILED", "판정할 항목을 선택하세요.", nil)
		return
	}
	if len(in.ItemIDs) > 1000 {
		problem(w, 422, "VALIDATION_FAILED", "한 번에 1000개까지 판정할 수 있습니다.", nil)
		return
	}
	if !reviewResults[in.Result] {
		problem(w, 422, "VALIDATION_FAILED", "검토 결과를 선택하세요.", nil)
		return
	}
	if in.FinalApplicability != "" && !contains([]string{"Y", "N", "N/A"}, in.FinalApplicability) {
		problem(w, 422, "VALIDATION_FAILED", "최종 적용 여부는 Y, N 또는 N/A여야 합니다.", nil)
		return
	}
	var status string
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT status FROM review_requests WHERE id=$1`, reviewID).Scan(&status); err != nil {
		problem(w, 404, "NOT_FOUND", "심의를 찾을 수 없습니다.", nil)
		return
	}
	if status != "REVIEWING" {
		problem(w, 409, "STATE_CONFLICT", "검토 중인 심의에서만 판정할 수 있습니다.", nil)
		return
	}
	// Without overwrite an item that already carries a verdict is left alone,
	// so a bulk judgement cannot quietly replace one made item by item.
	conflict := `ON CONFLICT(submission_item_id) DO NOTHING`
	if in.Overwrite {
		conflict = `ON CONFLICT(submission_item_id) DO UPDATE SET reviewer_id=EXCLUDED.reviewer_id,final_applicability=EXCLUDED.final_applicability,result=EXCLUDED.result,opinion=EXCLUDED.opinion,evidence_adequacy=EXCLUDED.evidence_adequacy,updated_at=now()`
	}
	tag, err := s.Store.Pool.Exec(r.Context(), `
                INSERT INTO review_results(id,submission_item_id,reviewer_id,final_applicability,result,opinion,evidence_adequacy)
                SELECT gen_random_uuid()::text,si.id,$1,$2,$3,$4,$5
                FROM submission_items si
                JOIN submissions sub ON sub.id=si.submission_id
                WHERE si.id = ANY($6) AND sub.review_request_id=$7
                  AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$7)
                `+conflict,
		session(r).User.ID, in.FinalApplicability, in.Result, in.Opinion, in.EvidenceAdequacy, in.ItemIDs, reviewID)
	if err != nil {
		s.fault(w, r, "UPDATE_FAILED", "일괄 판정에 실패했습니다.", err)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "BULK_REVIEW_RESULT", "REVIEW_REQUEST", reviewID, nil, map[string]any{"items": len(in.ItemIDs), "applied": tag.RowsAffected(), "result": in.Result, "overwrite": in.Overwrite}))
	jsonResponse(w, 200, map[string]any{"requested": len(in.ItemIDs), "applied": tag.RowsAffected(), "skipped": int64(len(in.ItemIDs)) - tag.RowsAffected()})
}

// markFollowUp records that an action promised at review time was carried
// out, or takes that back. The register that collects these promises could
// only grow before: an entry from last year looked the same whether it had
// been done or forgotten.
//
// Any security reviewer may close one, not only the reviewer who wrote it.
// These outlive the review -- the person who judged the item may have moved
// on long before the action falls due.
func (s *Server) markFollowUp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		// Action is "report" for the team that did the work, "confirm" for the
		// security side accepting it, and "reopen" to undo either.
		Action string `json:"action"`
		Done   bool   `json:"done"`
		Note   string `json:"note"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if len([]rune(in.Note)) > 2000 {
		problem(w, 422, "VALIDATION_FAILED", "조치 결과는 2000자 이내여야 합니다.", nil)
		return
	}
	// done:true was the whole vocabulary before reporting existed; it still
	// means what it did, so an existing integration keeps working.
	if in.Action == "" {
		in.Action = "reopen"
		if in.Done {
			in.Action = "confirm"
		}
	}
	sess := session(r)
	reviewID, err := s.reviewOfResult(r.Context(), id)
	if err != nil {
		problem(w, 404, "NOT_FOUND", "조치 사항이 기록된 검토 결과를 찾을 수 없습니다.", nil)
		return
	}
	reviewer := containsRole(sess.User, "SECURITY_REVIEWER")
	var query string
	var args []any
	var action string
	switch in.Action {
	case "report":
		// The people who carried the work out say so; the register still shows
		// the entry until the security side accepts it.
		if !reviewer && !s.canAccessReview(r.Context(), sess, reviewID) {
			problem(w, 403, "FORBIDDEN", "이 심의의 조치를 보고할 수 없습니다.", nil)
			return
		}
		query = `UPDATE review_results SET follow_up_reported_at=now(),follow_up_reported_by=$2,follow_up_note=$3 WHERE id=$1 AND btrim(follow_up)<>'' AND follow_up_done_at IS NULL`
		args = []any{id, sess.User.ID, strings.TrimSpace(in.Note)}
		action = "FOLLOW_UP_REPORTED"
	case "confirm":
		if !reviewer {
			problem(w, 403, "FORBIDDEN", "이행 확인은 보안 담당자만 할 수 있습니다.", nil)
			return
		}
		query = `UPDATE review_results SET follow_up_done_at=now(),follow_up_done_by=$2,follow_up_note=COALESCE(NULLIF($3,''),follow_up_note) WHERE id=$1 AND btrim(follow_up)<>''`
		args = []any{id, sess.User.ID, strings.TrimSpace(in.Note)}
		action = "FOLLOW_UP_DONE"
	case "reopen":
		if !reviewer {
			problem(w, 403, "FORBIDDEN", "이행 완료 해제는 보안 담당자만 할 수 있습니다.", nil)
			return
		}
		query = `UPDATE review_results SET follow_up_done_at=NULL,follow_up_done_by=NULL,follow_up_reported_at=NULL,follow_up_reported_by=NULL,follow_up_note='' WHERE id=$1 AND btrim(follow_up)<>''`
		args = []any{id}
		action = "FOLLOW_UP_REOPENED"
	default:
		problem(w, 422, "VALIDATION_FAILED", "작업은 report, confirm 또는 reopen이어야 합니다.", nil)
		return
	}
	tag, err := s.Store.Pool.Exec(r.Context(), query, args...)
	if err != nil {
		s.fault(w, r, "UPDATE_FAILED", "조치 상태를 저장하지 못했습니다.", err)
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "NOT_FOUND", "조치 사항이 기록된 검토 결과를 찾을 수 없습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, action, "REVIEW_REQUEST", reviewID, nil, map[string]any{"review_result_id": id, "note": in.Note}))
	// Each step tells the person waiting on it. Without this a report sits
	// unconfirmed until somebody happens to open the register, which is the
	// same silence the due-date reminders were added to break.
	s.notifyFollowUpStep(r.Context(), in.Action, id, reviewID, strings.TrimSpace(in.Note))
	jsonResponse(w, 200, map[string]any{"id": id, "action": in.Action})
}

func (s *Server) notifyFollowUpStep(ctx context.Context, action, resultID, reviewID, note string) {
	var number, service, reviewer, reported string
	if err := s.Store.Pool.QueryRow(ctx, `SELECT r.review_number,r.service_name,COALESCE(r.reviewer_id,''),COALESCE(rr.follow_up_reported_by,'')
                FROM review_results rr
                JOIN submission_items si ON si.id=rr.submission_item_id
                JOIN submissions sub ON sub.id=si.submission_id
                JOIN review_requests r ON r.id=sub.review_request_id
                WHERE rr.id=$1`, resultID).Scan(&number, &service, &reviewer, &reported); err != nil {
		return
	}
	switch action {
	case "report":
		s.addTargetedNotification(ctx, reviewer, "FOLLOW_UP_REPORTED", "후속조치 이행 보고",
			fmt.Sprintf("%s(%s)의 후속조치가 완료 보고되었습니다. 확인 후 이행 완료 처리하세요. %s", number, service, note), "REVIEW_REQUEST", reviewID)
	case "confirm":
		s.addTargetedNotification(ctx, reported, "FOLLOW_UP_DONE", "후속조치 이행 확인",
			fmt.Sprintf("%s(%s)에 보고한 후속조치가 확인되어 종료되었습니다.", number, service), "REVIEW_REQUEST", reviewID)
	}
}

// reviewOfResult finds the review a verdict belongs to, which decides who may
// report against it.
func (s *Server) reviewOfResult(ctx context.Context, resultID string) (string, error) {
	var reviewID string
	err := s.Store.Pool.QueryRow(ctx, `SELECT sub.review_request_id FROM review_results rr
                JOIN submission_items si ON si.id=rr.submission_item_id
                JOIN submissions sub ON sub.id=si.submission_id WHERE rr.id=$1 AND btrim(rr.follow_up)<>''`, resultID).Scan(&reviewID)
	return reviewID, err
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
		FollowUpDueDate    string `json:"follow_up_due_date"`
		NAApproved         *bool  `json:"na_approved"`
		ExpectedUpdatedAt  string `json:"expected_updated_at"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !reviewResults[in.Result] {
		problem(w, 422, "VALIDATION_FAILED", "검토 결과를 선택하세요.", nil)
		return
	}
	// An action with no date is chased by nothing: the reminder worker only
	// looks at dated ones, and the register can never call it overdue. A
	// commitment made in a verdict has to say when it is due.
	if field := tooLong(map[string]string{"opinion": in.Opinion, "follow_up": in.FollowUp}, longTextLimit); field != "" {
		problem(w, 422, "VALIDATION_FAILED", fmt.Sprintf("입력이 너무 깁니다. %d자 이내로 작성하세요.", longTextLimit), map[string]string{field: fmt.Sprintf("%d자를 넘습니다.", longTextLimit)})
		return
	}
	if strings.TrimSpace(in.FollowUp) != "" && strings.TrimSpace(in.FollowUpDueDate) == "" {
		problem(w, 422, "FOLLOW_UP_DUE_REQUIRED", "후속조치에는 조치 기한이 필요합니다. 기한이 없으면 알림도 지연 판정도 동작하지 않습니다.", map[string]string{"follow_up_due_date": "필수 입력 항목입니다."})
		return
	}
	// Two reviewers can hold the same review open, so the same protection the
	// author side has applies here.
	if conflict, ok := s.reviewResultConflict(r, itemID, in.ExpectedUpdatedAt); ok {
		problem(w, 409, "REVIEW_RESULT_CONFLICT", "다른 검토자가 이 항목을 먼저 저장했습니다. 최신 내용을 확인한 뒤 다시 저장하세요.", conflict)
		return
	}
	var savedAt time.Time
	err := s.Store.Pool.QueryRow(r.Context(), `INSERT INTO review_results(id,submission_item_id,reviewer_id,final_applicability,result,opinion,evidence_adequacy,na_approved,follow_up,follow_up_due_date) SELECT $1,si.id,$2,$3,$4,$5,$6,$7,$8,NULLIF($11,'')::date FROM submission_items si JOIN submissions sub ON sub.id=si.submission_id JOIN review_requests rq ON rq.id=sub.review_request_id WHERE si.id=$9 AND sub.review_request_id=$10 AND rq.status='REVIEWING' AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$10) ON CONFLICT(submission_item_id) DO UPDATE SET reviewer_id=EXCLUDED.reviewer_id,final_applicability=EXCLUDED.final_applicability,result=EXCLUDED.result,opinion=EXCLUDED.opinion,evidence_adequacy=EXCLUDED.evidence_adequacy,na_approved=EXCLUDED.na_approved,follow_up=EXCLUDED.follow_up,follow_up_due_date=EXCLUDED.follow_up_due_date,updated_at=now() RETURNING updated_at`, store.NewID(), session(r).User.ID, in.FinalApplicability, in.Result, in.Opinion, in.EvidenceAdequacy, in.NAApproved, in.FollowUp, itemID, id, strings.TrimSpace(in.FollowUpDueDate)).Scan(&savedAt)
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
	// Same reason a follow-up needs one: the reminder worker only looks at
	// dated change requests, and an undated one can never be reported as
	// overdue. A correction asked for without a date is asked for once.
	if field := tooLong(map[string]string{"reason": in.Reason}, longTextLimit); field != "" {
		problem(w, 422, "VALIDATION_FAILED", fmt.Sprintf("보완 사유는 %d자 이내로 작성하세요.", longTextLimit), map[string]string{field: "너무 깁니다."})
		return
	}
	if strings.TrimSpace(in.DueDate) == "" {
		problem(w, 422, "DUE_DATE_REQUIRED", "보완 요청에는 완료 예정일이 필요합니다. 기한이 없으면 알림도 지연 판정도 동작하지 않습니다.", map[string]string{"due_date": "필수 입력 항목입니다."})
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
		s.fault(w, r, "CREATE_FAILED", "보완 요청을 만들지 못했습니다.", err)
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
		s.fault(w, r, "UPDATE_FAILED", "보완 요청을 저장하지 못했습니다.", err)
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
	// Completing a review while items are unjudged is exactly what this guard
	// exists to prevent, and a failed count used to read as zero.
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM submissions sub JOIN submission_items si ON si.submission_id=sub.id LEFT JOIN review_results rr ON rr.submission_item_id=si.id WHERE sub.review_request_id=$1 AND sub.revision=(SELECT max(revision) FROM submissions WHERE review_request_id=$1) AND (rr.id IS NULL OR rr.result='')`, id).Scan(&missing); err != nil {
		s.fault(w, r, "QUERY_FAILED", "남은 항목을 확인하지 못해 검토 완료를 중단했습니다.", err)
		return
	}
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM change_requests WHERE review_request_id=$1 AND status<>'VERIFIED'`, id).Scan(&open); err != nil {
		s.fault(w, r, "QUERY_FAILED", "남은 항목을 확인하지 못해 검토 완료를 중단했습니다.", err)
		return
	}
	// A change request sends the review back, and the author can edit any item
	// while it is back -- not only the one that was asked about. A verdict
	// recorded before that edit was made against an answer that no longer
	// exists, so counting it as reviewed is a false all-clear.
	stale, err := s.staleVerdicts(r.Context(), id)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "남은 항목을 확인하지 못해 검토 완료를 중단했습니다.", err)
		return
	}
	if missing > 0 || open > 0 || stale > 0 {
		// Saying only that it cannot be completed leaves the reviewer hunting
		// through the checklist for what is left.
		var left []string
		for _, part := range []struct {
			count int
			label string
		}{{missing, "미검토 항목"}, {open, "미검증 보완 요청"}, {stale, "검토 후 답변이 바뀐 항목"}} {
			if part.count > 0 {
				left = append(left, fmt.Sprintf("%s %d건", part.label, part.count))
			}
		}
		problem(w, 422, "REVIEW_INCOMPLETE", strings.Join(left, ", ")+"이 남아 검토를 완료할 수 없습니다.", map[string]int{"unreviewed_items": missing, "unverified_changes": open, "stale_verdicts": stale})
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
	if field := tooLong(map[string]string{"final_opinion": in.FinalOpinion}, longTextLimit); field != "" {
		problem(w, 422, "VALIDATION_FAILED", fmt.Sprintf("최종 의견은 %d자 이내로 입력하세요.", longTextLimit), map[string]string{field: "너무 깁니다."})
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
		s.fault(w, r, "UPDATE_FAILED", "검토를 완료하지 못했습니다.", err)
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

// selfReviewBlocked reports whether this person may decide this review. The
// person who asked for a review is not a neutral judge of it, which is the
// premise the whole process rests on; an installation small enough that the
// same account has to do both can allow it deliberately.
func (s *Server) selfReviewBlocked(ctx context.Context, reviewID, userID string) bool {
	var workflow struct {
		AllowSelfReview bool `json:"allow_self_review"`
	}
	_, _ = s.Store.Setting(ctx, "workflow", &workflow)
	if workflow.AllowSelfReview {
		return false
	}
	var own bool
	if err := s.Store.Pool.QueryRow(ctx, `SELECT requester_id=$2 FROM review_requests WHERE id=$1`, reviewID, userID).Scan(&own); err != nil {
		return false
	}
	return own
}

func (s *Server) decideApproval(w http.ResponseWriter, r *http.Request, decision string) {
	id := r.PathValue("id")
	// The comment is optional, so an approval sent with no body at all -- the
	// obvious thing for an API client to do -- has to be accepted.
	var in struct {
		Comment string `json:"comment"`
	}
	if !decodeOptionalJSON(w, r, &in) {
		return
	}
	if field := tooLong(map[string]string{"comment": in.Comment}, longTextLimit); field != "" {
		problem(w, 422, "VALIDATION_FAILED", fmt.Sprintf("의견은 %d자 이내로 입력하세요.", longTextLimit), map[string]string{field: "너무 깁니다."})
		return
	}
	sess := session(r)
	// The queue already shows an unassigned approval to every approver, but
	// only the named approver could act on it, so a review that reached this
	// state without one -- enable the approval step after it was submitted and
	// it does -- sat in every queue and could not be decided by anyone. The
	// approver who does decide is recorded on the review.
	anyApprover := hasAnyRole(sess.User, "APPROVER")
	if s.selfReviewBlocked(r.Context(), id, sess.User.ID) {
		problem(w, 403, "SELF_REVIEW_FORBIDDEN", "본인이 신청한 심의는 본인이 승인할 수 없습니다. 다른 승인자를 지정하거나, 1인 운영이라면 서비스 설정에서 본인 심의 처리 허용을 켜십시오.", nil)
		return
	}
	// The approvals row is the decision itself -- who, what and why. Writing
	// it after the status had committed, with the error discarded, allowed a
	// review to read APPROVED with no record of anyone approving it.
	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		s.fault(w, r, "UPDATE_FAILED", "승인 처리에 실패했습니다.", err)
		return
	}
	defer tx.Rollback(r.Context())
	tag, err := tx.Exec(r.Context(), `UPDATE review_requests SET status=$2,approver_id=CASE WHEN approver_id IS NULL OR NOT `+stillHolds("approver_id", "APPROVER")+` THEN $3 ELSE approver_id END,final_result=CASE WHEN $2='REJECTED' THEN 'REJECTED' ELSE final_result END,approved_at=CASE WHEN $2='APPROVED' THEN now() ELSE approved_at END,updated_at=now() WHERE id=$1 AND status='APPROVAL_PENDING' AND (approver_id=$3 OR ((approver_id IS NULL OR NOT `+stillHolds("approver_id", "APPROVER")+`) AND $4))`, id, decision, sess.User.ID, anyApprover)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "STATE_CONFLICT", "승인 처리할 수 없습니다.", nil)
		return
	}
	if _, err = tx.Exec(r.Context(), `INSERT INTO approvals(id,review_request_id,approver_id,decision,comment) VALUES($1,$2,$3,$4,$5)`, store.NewID(), id, sess.User.ID, decision, in.Comment); err != nil {
		s.fault(w, r, "UPDATE_FAILED", "승인 처리에 실패했습니다.", err)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		s.fault(w, r, "UPDATE_FAILED", "승인 처리에 실패했습니다.", err)
		return
	}
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

// listParticipants answers who else is on a review. Participants could be
// added through the API and nowhere else, and there was no way to read them
// back at all -- so a requester could not see who they had given access to,
// and the co-author feature the user guide describes had no screen behind it.
func (s *Server) listParticipants(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.canAccessReview(r.Context(), session(r), id) {
		problem(w, 404, "NOT_FOUND", "심의를 찾을 수 없습니다.", nil)
		return
	}
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT p.user_id,u.display_name,u.department,u.active,p.participant_role
                FROM review_participants p JOIN users u ON u.id=p.user_id
                WHERE p.review_request_id=$1 ORDER BY u.display_name`, id)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "참여자를 불러오지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, []string{"user_id", "display_name", "department", "active", "participant_role"})
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "목록을 불러오지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, items)
}

// removeParticipant takes access away again -- somebody added by mistake, or
// somebody who has moved on. Without it, granting access was one-way.
func (s *Server) removeParticipant(w http.ResponseWriter, r *http.Request) {
	id, userID := r.PathValue("id"), r.PathValue("userID")
	if !s.canEditReview(r.Context(), session(r), id) {
		problem(w, 403, "FORBIDDEN", "참여자를 해제할 수 없습니다.", nil)
		return
	}
	var role string
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT participant_role FROM review_participants WHERE review_request_id=$1 AND user_id=$2`, id, userID).Scan(&role)
	tag, err := s.Store.Pool.Exec(r.Context(), `DELETE FROM review_participants WHERE review_request_id=$1 AND user_id=$2`, id, userID)
	if err != nil {
		s.fault(w, r, "UPDATE_FAILED", "참여자를 해제하지 못했습니다.", err)
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "NOT_FOUND", "참여자를 찾을 수 없습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "REMOVE_PARTICIPANT", "REVIEW_REQUEST", id, map[string]string{"user_id": userID, "role": role}, nil))
	w.WriteHeader(http.StatusNoContent)
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
		s.fault(w, r, "UPDATE_FAILED", "공동 작성자를 지정하지 못했습니다.", err)
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
		s.fault(w, r, "QUERY_FAILED", "Rule 후보를 불러오지 못했습니다.", err)
		return
	}
	candidates, err := scanDynamic(rows, []string{"source_item_id", "template_name", "template_version", "item_code", "section", "category", "title", "question", "severity", "assigned_item_id"})
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "항목 후보를 불러오지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, map[string]any{"editable": status == "DRAFT", "items": candidates})
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
		s.fault(w, r, "UPDATE_FAILED", "Rule 결과를 변경하지 못했습니다.", err)
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
		s.fault(w, r, "UPDATE_FAILED", "Rule 결과를 변경하지 못했습니다.", err)
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
		s.fault(w, r, "COPY_FAILED", "심의를 복사하지 못했습니다.", err)
		return
	}
	defer tx.Rollback(r.Context())
	number, err := s.nextReviewNumber(r, tx)
	if err != nil {
		s.fault(w, r, "COPY_FAILED", "심의번호를 발번하지 못했습니다.", err)
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
		s.fault(w, r, "COPY_FAILED", "심의를 복사하지 못했습니다.", err)
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
	_ = s.Store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM review_requests r WHERE r.id=$1 AND (r.requester_id=$2 OR r.builder_id=$2 OR r.developer_id=$2 OR r.operator_id=$2 OR r.reviewer_id=$2 OR r.approver_id=$2 OR EXISTS(SELECT 1 FROM review_participants p WHERE p.review_request_id=r.id AND p.user_id=$2)))`, id, sess.User.ID).Scan(&ok)
	return ok
}
func (s *Server) canEditReview(ctx context.Context, sess auth.Session, id string) bool {
	var ok bool
	_ = s.Store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM review_requests r WHERE r.id=$1 AND r.status IN ('DRAFT','CHANGE_REQUESTED') AND (r.requester_id=$2 OR r.builder_id=$2 OR r.developer_id=$2 OR r.operator_id=$2 OR EXISTS(SELECT 1 FROM review_participants p WHERE p.review_request_id=r.id AND p.user_id=$2 AND p.participant_role='CONTRIBUTOR')))`, id, sess.User.ID).Scan(&ok)
	return ok
}
func (s *Server) canReview(ctx context.Context, sess auth.Session, id string) bool {
	if !containsRole(sess.User, "SECURITY_REVIEWER") {
		return false
	}
	// Being named the reviewer of your own request does not make you one:
	// starting the review is refused, and so is everything it would allow.
	if s.selfReviewBlocked(ctx, id, sess.User.ID) {
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
	// A swallowed failure here used to roll the whole notification away in
	// silence, so the error is recorded even though delivery is best-effort.
	if err := s.Store.Notify(ctx, recipient, event, title, body, targetType, targetID); err != nil {
		s.Store.Log(ctx, "ERROR", "", "notification", "notification could not be recorded", map[string]any{"error": err.Error(), "event": event, "recipient": recipient})
	}
}

// notifyReviewer tells the assigned reviewer that a review is on their desk.
// An empty title and notice describe a first submission; a resubmission is not
// a new review, and saying so is what tells the reviewer to look for what moved
// rather than to start over.
func (s *Server) notifyReviewer(ctx context.Context, id, event, title, notice string) {
	var recipient, number, service string
	_ = s.Store.Pool.QueryRow(ctx, `SELECT COALESCE(reviewer_id,''),review_number,service_name FROM review_requests WHERE id=$1`, id).Scan(&recipient, &number, &service)
	if recipient == "" {
		return
	}
	if title == "" {
		title = "새 심의 제출"
	}
	if notice == "" {
		notice = "심의가 제출되었습니다. 검토를 시작하세요."
	}
	// The message used to quote the internal UUID, which means nothing to the
	// person reading it.
	s.addTargetedNotification(ctx, recipient, event, title, fmt.Sprintf("%s(%s) %s", number, service, notice), "REVIEW_REQUEST", id)
}

var _ = errors.Is
