package web

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/hkjang/SecCheck/internal/store"
)

var controlCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{1,31}$`)

func (s *Server) listControls(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	args := []any{}
	where := "TRUE"
	if q != "" {
		args = append(args, "%"+q+"%")
		where = `(c.code ILIKE $1 OR c.title ILIKE $1 OR c.description ILIKE $1)`
	}
	// The counts used to come from a GROUP BY over a four-table join, which
	// aggregated every submission item in the installation on every page load.
	// Correlated sub-queries let each count use its own index instead.
	var total int64
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM security_controls c WHERE `+where, args...).Scan(&total); err != nil {
		s.fault(w, r, "QUERY_FAILED", "Security Control을 불러오지 못했습니다.", err)
		return
	}
	limit, offset := parsePage(r)
	paged := append(append([]any{}, args...), limit, offset)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT c.id,c.code,c.title,c.description,c.owner_id,COALESCE(u.display_name,'') AS owner,c.created_at,c.updated_at,
                (SELECT count(*) FROM checklist_items i WHERE i.control_id=c.id) AS mapped_items,
                (SELECT count(DISTINCT sub.review_request_id) FROM checklist_items i JOIN submission_items si ON si.source_item_id=i.id JOIN submissions sub ON sub.id=si.submission_id WHERE i.control_id=c.id) AS affected_reviews
                FROM security_controls c LEFT JOIN users u ON u.id=c.owner_id WHERE `+where+
		` ORDER BY c.code LIMIT $`+intString(len(paged)-1)+` OFFSET $`+intString(len(paged)), paged...)
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "Security Control을 불러오지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, []string{"id", "code", "title", "description", "owner_id", "owner", "created_at", "updated_at", "mapped_items", "affected_reviews"})
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "Security Control을 불러오지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset, "has_more": int64(offset+len(items)) < total})
}

type controlInput struct {
	Code        string `json:"code"`
	Title       string `json:"title"`
	Description string `json:"description"`
	OwnerID     string `json:"owner_id"`
}

func normalizeControlInput(in *controlInput) bool {
	in.Code = strings.ToUpper(strings.TrimSpace(in.Code))
	in.Title = strings.TrimSpace(in.Title)
	in.Description = strings.TrimSpace(in.Description)
	return controlCodePattern.MatchString(in.Code) && in.Title != "" && len([]rune(in.Title)) <= 300 && len([]rune(in.Description)) <= 4000
}

func (s *Server) createControl(w http.ResponseWriter, r *http.Request) {
	var in controlInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if !normalizeControlInput(&in) {
		problem(w, 422, "VALIDATION_FAILED", "Control 코드, 제목 및 길이를 확인하세요.", nil)
		return
	}
	id := store.NewID()
	_, err := s.Store.Pool.Exec(r.Context(), `INSERT INTO security_controls(id,code,title,description,owner_id) VALUES($1,$2,$3,$4,NULLIF($5,''))`, id, in.Code, in.Title, in.Description, in.OwnerID)
	if err != nil {
		problem(w, 409, "CREATE_FAILED", "중복 코드 또는 담당자를 확인하세요.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "CREATE_CONTROL", "SECURITY_CONTROL", id, nil, in))
	jsonResponse(w, 201, map[string]string{"id": id})
}

// The same body shape as a create, except that a field left out keeps the
// value the Control already has -- the route is a PATCH, and an admin who
// renames a Control should not lose its description with it.
type controlPatch struct {
	Code        *string `json:"code"`
	Title       *string `json:"title"`
	Description *string `json:"description"`
	OwnerID     *string `json:"owner_id"`
}

func normalizeControlPatch(in *controlPatch) bool {
	in.Code, in.Title, in.Description, in.OwnerID = trimmedPatch(in.Code), trimmedPatch(in.Title), trimmedPatch(in.Description), trimmedPatch(in.OwnerID)
	if in.Code != nil {
		upper := strings.ToUpper(*in.Code)
		in.Code = &upper
		if !controlCodePattern.MatchString(upper) {
			return false
		}
	}
	if in.Title != nil && (*in.Title == "" || len([]rune(*in.Title)) > 300) {
		return false
	}
	return in.Description == nil || len([]rune(*in.Description)) <= 4000
}

func (s *Server) updateControl(w http.ResponseWriter, r *http.Request) {
	var in controlPatch
	if !decodeJSON(w, r, &in) {
		return
	}
	if !normalizeControlPatch(&in) {
		problem(w, 422, "VALIDATION_FAILED", "Control 코드, 제목 및 길이를 확인하세요.", nil)
		return
	}
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE security_controls SET code=COALESCE($2::text,code),title=COALESCE($3::text,title),description=COALESCE($4::text,description),owner_id=CASE WHEN $5::bool THEN NULLIF($6::text,'') ELSE owner_id END,updated_at=now() WHERE id=$1`, r.PathValue("id"), in.Code, in.Title, in.Description, in.OwnerID != nil, in.OwnerID)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "UPDATE_FAILED", "Control을 저장하지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPDATE_CONTROL", "SECURITY_CONTROL", r.PathValue("id"), nil, in))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteControl(w http.ResponseWriter, r *http.Request) {
	var mapped int
	// A guard whose query failed used to read as "nothing is mapped", so a
	// database hiccup was enough to let a Control that items point at be
	// deleted. A check that cannot run has not passed.
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM checklist_items WHERE control_id=$1`, r.PathValue("id")).Scan(&mapped); err != nil {
		s.fault(w, r, "QUERY_FAILED", "연결된 항목을 확인하지 못해 삭제를 중단했습니다.", err)
		return
	}
	if mapped > 0 {
		problem(w, 409, "CONTROL_IN_USE", "체크리스트 항목 연결을 먼저 해제하세요.", map[string]int{"mapped_items": mapped})
		return
	}
	// The row is about to be gone, so what it was has to be captured now: an
	// audit entry naming only an identifier that no longer resolves cannot be
	// read back, which defeats the point of recording the deletion.
	var code, title string
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT code,title FROM security_controls WHERE id=$1`, r.PathValue("id")).Scan(&code, &title)
	tag, err := s.Store.Pool.Exec(r.Context(), `DELETE FROM security_controls WHERE id=$1`, r.PathValue("id"))
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 404, "NOT_FOUND", "Control을 찾을 수 없습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "DELETE_CONTROL", "SECURITY_CONTROL", r.PathValue("id"), map[string]any{"code": code, "title": title}, nil))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) controlImpact(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT i.id,t.name,v.version,i.item_code,i.title,v.status,count(DISTINCT sub.review_request_id) AS affected_reviews FROM checklist_items i JOIN checklist_versions v ON v.id=i.version_id JOIN checklist_templates t ON t.id=v.template_id LEFT JOIN submission_items si ON si.source_item_id=i.id LEFT JOIN submissions sub ON sub.id=si.submission_id WHERE i.control_id=$1 GROUP BY i.id,t.name,v.version,v.status,v.created_at,i.sort_order ORDER BY t.name,v.created_at DESC,i.sort_order`, r.PathValue("id"))
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "영향 범위를 불러오지 못했습니다.", err)
		return
	}
	items, err := scanDynamic(rows, []string{"item_id", "template_name", "template_version", "item_code", "title", "version_status", "affected_reviews"})
	if err != nil {
		s.fault(w, r, "QUERY_FAILED", "목록을 불러오지 못했습니다.", err)
		return
	}
	jsonResponse(w, 200, items)
}
