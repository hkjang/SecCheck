package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/xuri/excelize/v2"
)

// listTemplates is paginated and searchable like the review list. An
// installation that imports a workbook per team accumulates templates the same
// way it accumulates reviews, and a fixed unbounded list stops being usable.
func (s *Server) listTemplates(w http.ResponseWriter, r *http.Request) {
	where := "TRUE"
	args := []any{}
	query := r.URL.Query()
	if term := strings.TrimSpace(query.Get("q")); term != "" {
		args = append(args, "%"+term+"%")
		n := intString(len(args))
		where += " AND (t.name ILIKE $" + n + " OR t.description ILIKE $" + n + " OR t.category ILIKE $" + n + ")"
	}
	if category := strings.TrimSpace(query.Get("category")); category != "" {
		args = append(args, category)
		where += " AND t.category=$" + intString(len(args))
	}
	switch strings.TrimSpace(query.Get("active")) {
	case "1":
		where += " AND t.active"
	case "0":
		where += " AND NOT t.active"
	}
	var total int64
	if err := s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM checklist_templates t WHERE `+where, args...).Scan(&total); err != nil {
		problem(w, 500, "QUERY_FAILED", "템플릿을 불러오지 못했습니다.", nil)
		return
	}
	limit, offset := parsePage(r)
	paged := append(append([]any{}, args...), limit, offset)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT t.id,t.name,t.category,t.description,t.active,t.created_at,t.updated_at,COALESCE((SELECT jsonb_agg(jsonb_build_object('id',v.id,'version',v.version,'status',v.status,'change_note',v.change_note,'source_filename',v.source_filename,'published_at',v.published_at,'created_at',v.created_at) ORDER BY v.created_at DESC) FROM checklist_versions v WHERE v.template_id=t.id),'[]') FROM checklist_templates t WHERE `+where+
		` ORDER BY t.category,t.name LIMIT $`+intString(len(paged)-1)+` OFFSET $`+intString(len(paged)), paged...)
	if err != nil {
		problem(w, 500, "QUERY_FAILED", "템플릿을 불러오지 못했습니다.", nil)
		return
	}
	items := scanDynamic(rows, []string{"id", "name", "category", "description", "active", "created_at", "updated_at", "versions"})
	jsonResponse(w, 200, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset, "has_more": int64(offset+len(items)) < total})
}

func (s *Server) createTemplate(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Category, Description, Version string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Name == "" || in.Category == "" {
		problem(w, 422, "VALIDATION_FAILED", "템플릿 이름과 분류가 필요합니다.", nil)
		return
	}
	if in.Version == "" {
		in.Version = "V1.0"
	}
	tid, vid := store.NewID(), store.NewID()
	tx, err := s.Store.Pool.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO checklist_templates(id,name,category,description,created_by) VALUES($1,$2,$3,$4,$5)`, tid, in.Name, strings.ToUpper(in.Category), in.Description, session(r).User.ID)
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO checklist_versions(id,template_id,version,created_by) VALUES($1,$2,$3,$4)`, vid, tid, in.Version, session(r).User.ID)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		} else {
			_ = tx.Rollback(r.Context())
		}
	}
	if err != nil {
		problem(w, 409, "CREATE_FAILED", "템플릿을 만들지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "CREATE_TEMPLATE", "TEMPLATE", tid, nil, in))
	jsonResponse(w, 201, map[string]string{"id": tid, "version_id": vid})
}

func (s *Server) getTemplate(w http.ResponseWriter, r *http.Request) {
	var t []byte
	err := s.Store.Pool.QueryRow(r.Context(), `SELECT to_jsonb(t)||jsonb_build_object('versions',COALESCE((SELECT jsonb_agg(to_jsonb(v)||jsonb_build_object('items',COALESCE((SELECT jsonb_agg(to_jsonb(i)||jsonb_build_object('section',COALESCE(sec.name,'')) ORDER BY i.sort_order) FROM checklist_items i LEFT JOIN checklist_sections sec ON sec.id=i.section_id WHERE i.version_id=v.id),'[]')) ORDER BY v.created_at DESC) FROM checklist_versions v WHERE v.template_id=t.id),'[]')) FROM checklist_templates t WHERE t.id=$1`, r.PathValue("id")).Scan(&t)
	if err != nil {
		problem(w, 404, "NOT_FOUND", "템플릿을 찾을 수 없습니다.", nil)
		return
	}
	var out any
	_ = json.Unmarshal(t, &out)
	jsonResponse(w, 200, out)
}

func (s *Server) updateTemplate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, Description string
		Active            *bool
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	active := true
	if in.Active != nil {
		active = *in.Active
	}
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE checklist_templates SET name=COALESCE(NULLIF($2,''),name),description=$3,active=$4,updated_at=now() WHERE id=$1`, r.PathValue("id"), in.Name, in.Description, active)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 404, "NOT_FOUND", "템플릿을 찾을 수 없습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPDATE_TEMPLATE", "TEMPLATE", r.PathValue("id"), nil, in))
	w.WriteHeader(204)
}

// deleteTemplate removes a template that was never used. A mis-imported
// workbook previously had to be left behind for ever; anything that has been
// published or snapshotted into a review is refused, because a submission
// snapshot must stay explainable.
func (s *Server) deleteTemplate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var name string
	var published, used int
	err := s.Store.Pool.QueryRow(r.Context(), `SELECT t.name,
                (SELECT count(*) FROM checklist_versions v WHERE v.template_id=t.id AND v.status<>'DRAFT'),
                (SELECT count(*) FROM submission_items si JOIN checklist_items i ON i.id=si.source_item_id JOIN checklist_versions v ON v.id=i.version_id WHERE v.template_id=t.id)
                FROM checklist_templates t WHERE t.id=$1`, id).Scan(&name, &published, &used)
	if err != nil {
		problem(w, 404, "NOT_FOUND", "템플릿을 찾을 수 없습니다.", nil)
		return
	}
	if published > 0 || used > 0 {
		problem(w, 409, "TEMPLATE_IN_USE", "게시되었거나 심의에 사용된 템플릿은 삭제할 수 없습니다. 사용 중지로 변경하세요.",
			map[string]any{"published_versions": published, "snapshotted_items": used})
		return
	}
	if _, err = s.Store.Pool.Exec(r.Context(), `DELETE FROM checklist_templates WHERE id=$1`, id); err != nil {
		problem(w, 409, "DELETE_FAILED", "템플릿을 삭제하지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "DELETE_TEMPLATE", "TEMPLATE", id, map[string]any{"name": name}, nil))
	w.WriteHeader(204)
}

func (s *Server) copyTemplate(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("id")
	var in struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		problem(w, 500, "COPY_FAILED", "템플릿을 복제하지 못했습니다.", nil)
		return
	}
	defer tx.Rollback(r.Context())
	tid, vid := store.NewID(), store.NewID()
	tag, err := tx.Exec(r.Context(), `INSERT INTO checklist_templates(id,name,category,description,created_by) SELECT $2,COALESCE(NULLIF($3,''),name||' 복사본'),category,description,$4 FROM checklist_templates WHERE id=$1`, source, tid, in.Name, session(r).User.ID)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 404, "NOT_FOUND", "원본 템플릿을 찾을 수 없습니다.", nil)
		return
	}
	var srcVersion string
	err = tx.QueryRow(r.Context(), `SELECT id FROM checklist_versions WHERE template_id=$1 ORDER BY created_at DESC LIMIT 1`, source).Scan(&srcVersion)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO checklist_versions(id,template_id,version,status,change_note,created_by) VALUES($1,$2,'V1.0','DRAFT','템플릿 복제',$3)`, vid, tid, session(r).User.ID)
	}
	if err == nil {
		err = cloneVersion(r.Context(), tx, srcVersion, vid)
	}
	if err != nil {
		problem(w, 500, "COPY_FAILED", "템플릿을 복제하지 못했습니다.", nil)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		problem(w, 500, "COPY_FAILED", "템플릿을 복제하지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "CREATE_TEMPLATE", "TEMPLATE", tid, map[string]string{"source": source}, map[string]string{"name": in.Name}))
	jsonResponse(w, 201, map[string]string{"id": tid, "version_id": vid})
}

func (s *Server) createTemplateVersion(w http.ResponseWriter, r *http.Request) {
	tid := r.PathValue("id")
	var in struct {
		Version       string `json:"version"`
		ChangeNote    string `json:"change_note"`
		BaseVersionID string `json:"base_version_id"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Version == "" {
		problem(w, 422, "VALIDATION_FAILED", "버전이 필요합니다.", nil)
		return
	}
	vid := store.NewID()
	tx, err := s.Store.Pool.Begin(r.Context())
	if err == nil {
		tag, e := tx.Exec(r.Context(), `INSERT INTO checklist_versions(id,template_id,version,change_note,created_by) SELECT $1,id,$3,$4,$5 FROM checklist_templates WHERE id=$2`, vid, tid, in.Version, in.ChangeNote, session(r).User.ID)
		err = e
		if err == nil && tag.RowsAffected() == 0 {
			err = pgx.ErrNoRows
		}
		if err == nil && in.BaseVersionID != "" {
			err = cloneVersion(r.Context(), tx, in.BaseVersionID, vid)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		} else {
			_ = tx.Rollback(r.Context())
		}
	}
	if err != nil {
		problem(w, 409, "CREATE_FAILED", "새 버전을 만들지 못했습니다. 버전 값과 원본 버전을 확인하세요.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "CREATE_TEMPLATE_VERSION", "CHECKLIST_VERSION", vid, nil, in))
	jsonResponse(w, 201, map[string]string{"id": vid})
}

func cloneVersion(ctx context.Context, tx pgx.Tx, source, target string) error {
	rows, err := tx.Query(ctx, `SELECT id,name,sort_order FROM checklist_sections WHERE version_id=$1`, source)
	if err != nil {
		return err
	}
	type sourceSection struct {
		old, name string
		order     int
	}
	sections := []sourceSection{}
	for rows.Next() {
		var v sourceSection
		if err = rows.Scan(&v.old, &v.name, &v.order); err != nil {
			rows.Close()
			return err
		}
		sections = append(sections, v)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	sectionMap := map[string]string{}
	for _, section := range sections {
		newID := store.NewID()
		sectionMap[section.old] = newID
		if _, err = tx.Exec(ctx, `INSERT INTO checklist_sections(id,version_id,name,sort_order) VALUES($1,$2,$3,$4)`, newID, target, section.name, section.order); err != nil {
			return err
		}
	}
	rows, err = tx.Query(ctx, `SELECT section_id,control_id,item_code,category,title,question,guide,legal_basis,example,severity,required,answer_type,evidence_required,applicability_rule,options_json,sort_order FROM checklist_items WHERE version_id=$1 ORDER BY sort_order`, source)
	if err != nil {
		return err
	}
	type sourceItem struct {
		sec, control                                                             *string
		code, category, title, question, guide, legal, example, severity, answer string
		required, evidence                                                       bool
		rule, opts                                                               []byte
		order                                                                    int
	}
	items := []sourceItem{}
	for rows.Next() {
		var v sourceItem
		if err = rows.Scan(&v.sec, &v.control, &v.code, &v.category, &v.title, &v.question, &v.guide, &v.legal, &v.example, &v.severity, &v.required, &v.answer, &v.evidence, &v.rule, &v.opts, &v.order); err != nil {
			rows.Close()
			return err
		}
		items = append(items, v)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, v := range items {
		var newSec any
		if v.sec != nil {
			newSec = sectionMap[*v.sec]
		}
		_, err = tx.Exec(ctx, `INSERT INTO checklist_items(id,version_id,section_id,control_id,item_code,category,title,question,guide,legal_basis,example,severity,required,answer_type,evidence_required,applicability_rule,options_json,sort_order) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, store.NewID(), target, newSec, v.control, v.code, v.category, v.title, v.question, v.guide, v.legal, v.example, v.severity, v.required, v.answer, v.evidence, v.rule, v.opts, v.order)
		if err != nil {
			return err
		}
	}
	return nil
}

type itemInput struct {
	Section           string `json:"section"`
	ControlID         string `json:"control_id"`
	ItemCode          string `json:"item_code"`
	Category          string `json:"category"`
	Title             string `json:"title"`
	Question          string `json:"question"`
	Guide             string `json:"guide"`
	LegalBasis        string `json:"legal_basis"`
	Example           string `json:"example"`
	Severity          string `json:"severity"`
	AnswerType        string `json:"answer_type"`
	Required          bool   `json:"required"`
	EvidenceRequired  bool   `json:"evidence_required"`
	ApplicabilityRule any    `json:"applicability_rule"`
	Options           any    `json:"options"`
	SortOrder         int    `json:"sort_order"`
}

func (s *Server) createTemplateItem(w http.ResponseWriter, r *http.Request) {
	var in itemInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.ItemCode == "" || in.Title == "" || in.Question == "" {
		problem(w, 422, "VALIDATION_FAILED", "항목 코드, 제목 및 질문이 필요합니다.", nil)
		return
	}
	id := store.NewID()
	secID, err := s.sectionID(r.Context(), r.PathValue("versionID"), in.Section)
	if err != nil {
		problem(w, 500, "CREATE_FAILED", "섹션을 만들지 못했습니다.", nil)
		return
	}
	rule, _ := json.Marshal(in.ApplicabilityRule)
	opts, _ := json.Marshal(in.Options)
	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		problem(w, 500, "CREATE_FAILED", "항목을 만들지 못했습니다.", nil)
		return
	}
	defer tx.Rollback(r.Context())
	tag, err := tx.Exec(r.Context(), `INSERT INTO checklist_items(id,version_id,section_id,item_code,category,title,question,guide,legal_basis,example,severity,required,answer_type,evidence_required,applicability_rule,options_json,sort_order) SELECT $1,v.id,NULLIF($2,''),$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16 FROM checklist_versions v WHERE v.id=$17 AND v.template_id=$18 AND v.status='DRAFT'`, id, secID, in.ItemCode, in.Category, in.Title, in.Question, in.Guide, in.LegalBasis, in.Example, valueDefault(in.Severity, "MEDIUM"), in.Required, valueDefault(in.AnswerType, "YNNA"), in.EvidenceRequired, rule, opts, in.SortOrder, r.PathValue("versionID"), r.PathValue("id"))
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "IMMUTABLE_VERSION", "게시된 버전은 수정할 수 없습니다.", nil)
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE checklist_items SET control_id=NULLIF($2,'') WHERE id=$1`, id, in.ControlID); err != nil {
		problem(w, 422, "VALIDATION_FAILED", "Security Control 연결을 확인하세요.", nil)
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO template_changes(id,version_id,item_code,change_type,after_json,changed_by) SELECT $1,version_id,item_code,'ADD',to_jsonb(checklist_items),$2 FROM checklist_items WHERE id=$3`, store.NewID(), session(r).User.ID, id)
	if err != nil || tx.Commit(r.Context()) != nil {
		problem(w, 500, "CREATE_FAILED", "항목 변경 이력을 저장하지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPDATE_TEMPLATE", "CHECKLIST_ITEM", id, nil, in))
	jsonResponse(w, 201, map[string]string{"id": id})
}
func (s *Server) updateTemplateItem(w http.ResponseWriter, r *http.Request) {
	var in itemInput
	if !decodeJSON(w, r, &in) {
		return
	}
	secID, err := s.sectionID(r.Context(), r.PathValue("versionID"), in.Section)
	if err != nil {
		problem(w, 500, "UPDATE_FAILED", "섹션을 만들지 못했습니다.", nil)
		return
	}
	rule, _ := json.Marshal(in.ApplicabilityRule)
	opts, _ := json.Marshal(in.Options)
	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		problem(w, 500, "UPDATE_FAILED", "항목을 저장하지 못했습니다.", nil)
		return
	}
	defer tx.Rollback(r.Context())
	var before []byte
	_ = tx.QueryRow(r.Context(), `SELECT to_jsonb(i) FROM checklist_items i JOIN checklist_versions v ON v.id=i.version_id WHERE i.id=$1 AND i.version_id=$2 AND v.template_id=$3 AND v.status='DRAFT' FOR UPDATE`, r.PathValue("itemID"), r.PathValue("versionID"), r.PathValue("id")).Scan(&before)
	tag, err := tx.Exec(r.Context(), `UPDATE checklist_items i SET section_id=NULLIF($4,''),item_code=$5,category=$6,title=$7,question=$8,guide=$9,legal_basis=$10,example=$11,severity=$12,required=$13,answer_type=$14,evidence_required=$15,applicability_rule=$16,options_json=$17,sort_order=$18,control_id=NULLIF($19,'') FROM checklist_versions v WHERE i.id=$1 AND i.version_id=$2 AND v.id=i.version_id AND v.template_id=$3 AND v.status='DRAFT'`, r.PathValue("itemID"), r.PathValue("versionID"), r.PathValue("id"), secID, in.ItemCode, in.Category, in.Title, in.Question, in.Guide, in.LegalBasis, in.Example, valueDefault(in.Severity, "MEDIUM"), in.Required, valueDefault(in.AnswerType, "YNNA"), in.EvidenceRequired, rule, opts, in.SortOrder, in.ControlID)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "IMMUTABLE_VERSION", "게시된 버전은 수정할 수 없습니다.", nil)
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO template_changes(id,version_id,item_code,change_type,before_json,after_json,changed_by) SELECT $1,version_id,item_code,'MODIFY',$2,to_jsonb(checklist_items),$3 FROM checklist_items WHERE id=$4`, store.NewID(), before, session(r).User.ID, r.PathValue("itemID"))
	if err != nil || tx.Commit(r.Context()) != nil {
		problem(w, 500, "UPDATE_FAILED", "항목 변경 이력을 저장하지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPDATE_TEMPLATE", "CHECKLIST_ITEM", r.PathValue("itemID"), nil, in))
	w.WriteHeader(204)
}
func (s *Server) deleteTemplateItem(w http.ResponseWriter, r *http.Request) {
	tx, err := s.Store.Pool.Begin(r.Context())
	if err != nil {
		problem(w, 500, "DELETE_FAILED", "항목을 삭제하지 못했습니다.", nil)
		return
	}
	defer tx.Rollback(r.Context())
	var before []byte
	var code string
	_ = tx.QueryRow(r.Context(), `SELECT to_jsonb(i),i.item_code FROM checklist_items i JOIN checklist_versions v ON v.id=i.version_id WHERE i.id=$1 AND i.version_id=$2 AND v.template_id=$3 AND v.status='DRAFT' FOR UPDATE`, r.PathValue("itemID"), r.PathValue("versionID"), r.PathValue("id")).Scan(&before, &code)
	tag, err := tx.Exec(r.Context(), `DELETE FROM checklist_items i USING checklist_versions v WHERE i.id=$1 AND i.version_id=$2 AND v.id=i.version_id AND v.template_id=$3 AND v.status='DRAFT'`, r.PathValue("itemID"), r.PathValue("versionID"), r.PathValue("id"))
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "IMMUTABLE_VERSION", "게시된 버전은 수정할 수 없습니다.", nil)
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO template_changes(id,version_id,item_code,change_type,before_json,changed_by) VALUES($1,$2,$3,'DELETE',$4,$5)`, store.NewID(), r.PathValue("versionID"), code, before, session(r).User.ID)
	if err != nil || tx.Commit(r.Context()) != nil {
		problem(w, 500, "DELETE_FAILED", "항목 변경 이력을 저장하지 못했습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "UPDATE_TEMPLATE", "CHECKLIST_ITEM", r.PathValue("itemID"), nil, map[string]bool{"deleted": true}))
	w.WriteHeader(204)
}
func (s *Server) sectionID(ctx context.Context, version, name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", nil
	}
	var id string
	err := s.Store.Pool.QueryRow(ctx, `SELECT id FROM checklist_sections WHERE version_id=$1 AND name=$2`, version, name).Scan(&id)
	if err == nil {
		return id, nil
	}
	id = store.NewID()
	_ = s.Store.Pool.QueryRow(ctx, `SELECT COALESCE(max(sort_order),0)+1 FROM checklist_sections WHERE version_id=$1`, version).Scan(new(int))
	_, err = s.Store.Pool.Exec(ctx, `INSERT INTO checklist_sections(id,version_id,name,sort_order) VALUES($1,$2,$3,(SELECT COALESCE(max(sort_order),0)+1 FROM checklist_sections WHERE version_id=$2))`, id, version, name)
	return id, err
}

func (s *Server) publishVersion(w http.ResponseWriter, r *http.Request) {
	vid := r.PathValue("versionID")
	var count int
	_ = s.Store.Pool.QueryRow(r.Context(), `SELECT count(*) FROM checklist_items WHERE version_id=$1`, vid).Scan(&count)
	if count == 0 {
		problem(w, 422, "EMPTY_VERSION", "항목이 없는 버전은 게시할 수 없습니다.", nil)
		return
	}
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE checklist_versions SET status='PUBLISHED',published_by=$3,published_at=now() WHERE id=$1 AND template_id=$2 AND status='DRAFT'`, vid, r.PathValue("id"), session(r).User.ID)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "STATE_CONFLICT", "초안 버전만 게시할 수 있습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "PUBLISH_TEMPLATE", "CHECKLIST_VERSION", vid, nil, map[string]any{"items": count}))
	jsonResponse(w, 200, map[string]string{"status": "PUBLISHED"})
}
func (s *Server) retireVersion(w http.ResponseWriter, r *http.Request) {
	tag, err := s.Store.Pool.Exec(r.Context(), `UPDATE checklist_versions SET status='RETIRED' WHERE id=$1 AND template_id=$2 AND status='PUBLISHED'`, r.PathValue("versionID"), r.PathValue("id"))
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 409, "STATE_CONFLICT", "게시된 버전만 사용 중지할 수 있습니다.", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "RETIRE_TEMPLATE", "CHECKLIST_VERSION", r.PathValue("versionID"), nil, nil))
	w.WriteHeader(204)
}

func (s *Server) versionDiff(w http.ResponseWriter, r *http.Request) {
	current := r.PathValue("versionID")
	base := r.URL.Query().Get("base")
	if base == "" {
		_ = s.Store.Pool.QueryRow(r.Context(), `SELECT id FROM checklist_versions WHERE template_id=$1 AND created_at<(SELECT created_at FROM checklist_versions WHERE id=$2) ORDER BY created_at DESC LIMIT 1`, r.PathValue("id"), current).Scan(&base)
	}
	rows, err := s.Store.Pool.Query(r.Context(), `WITH a AS (SELECT item_code,to_jsonb(checklist_items)-'id'-'version_id' AS value FROM checklist_items WHERE version_id=$1),b AS (SELECT item_code,to_jsonb(checklist_items)-'id'-'version_id' AS value FROM checklist_items WHERE version_id=$2) SELECT COALESCE(a.item_code,b.item_code),CASE WHEN b.item_code IS NULL THEN 'ADD' WHEN a.item_code IS NULL THEN 'DELETE' WHEN a.value<>b.value THEN 'MODIFY' ELSE 'UNCHANGED' END,a.value,b.value FROM a FULL JOIN b USING(item_code) WHERE a.value IS DISTINCT FROM b.value ORDER BY COALESCE(a.item_code,b.item_code)`, current, base)
	if err != nil {
		problem(w, 500, "DIFF_FAILED", "버전을 비교하지 못했습니다.", nil)
		return
	}
	jsonResponse(w, 200, map[string]any{"base_version_id": base, "current_version_id": current, "changes": scanDynamic(rows, []string{"item_code", "change_type", "current", "base"})})
}

func (s *Server) versionChanges(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT c.id,c.item_code,c.change_type,c.before_json,c.after_json,u.display_name AS changed_by,c.created_at FROM template_changes c JOIN checklist_versions v ON v.id=c.version_id JOIN users u ON u.id=c.changed_by WHERE c.version_id=$1 AND v.template_id=$2 ORDER BY c.created_at DESC LIMIT 500`, r.PathValue("versionID"), r.PathValue("id"))
	if err != nil {
		problem(w, 500, "QUERY_FAILED", "변경 이력을 불러오지 못했습니다.", nil)
		return
	}
	jsonResponse(w, 200, scanDynamic(rows, []string{"id", "item_code", "change_type", "before", "after", "changed_by", "created_at"}))
}

type importColumn struct {
	Index  int    `json:"index"`
	Header string `json:"header"`
	Field  string `json:"field"`
}

func (s *Server) previewImport(w http.ResponseWriter, r *http.Request) {
	file, name, err := readWorkbookUpload(w, r)
	if err != nil {
		problem(w, 422, "IMPORT_FAILED", err.Error(), nil)
		return
	}
	defer file.Close()
	f, err := excelize.OpenReader(file)
	if err != nil {
		problem(w, 422, "IMPORT_FAILED", "Excel 파일을 읽을 수 없습니다.", nil)
		return
	}
	defer f.Close()
	sheets := []map[string]any{}
	for _, sheet := range f.GetSheetList() {
		rows, _ := f.GetRows(sheet)
		headerRow, mapping := detectHeaders(rows)
		fields := map[int]string{}
		for _, column := range mapping {
			fields[column.Index] = column.Field
		}
		columns := []importColumn{}
		if headerRow >= 0 && headerRow < len(rows) {
			for index, header := range rows[headerRow] {
				columns = append(columns, importColumn{Index: index, Header: header, Field: fields[index]})
			}
		}
		preview := []any{}
		for i := headerRow; i < len(rows) && i < headerRow+5; i++ {
			preview = append(preview, rows[i])
		}
		// Run the real parser so the wizard shows what would actually be
		// created, not just the first few spreadsheet rows.
		category := inferCategory(sheet)
		parsed, report := parseImportRowsWithReport(rows, headerRow, mapping, category)
		sample := []itemInput{}
		for i := 0; i < len(parsed) && i < 10; i++ {
			sample = append(sample, parsed[i])
		}
		sheets = append(sheets, map[string]any{
			"name": sheet, "rows": len(rows), "header_row": headerRow + 1,
			"mapping": mapping, "columns": columns, "preview": preview,
			"category": category, "version": extractVersion(sheet),
			"report": report, "items": sample,
		})
	}
	jsonResponse(w, 200, map[string]any{"filename": name, "sheets": sheets})
}

func readWorkbookUpload(w http.ResponseWriter, r *http.Request) (io.ReadCloser, string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 50<<20)
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		return nil, "", fmt.Errorf("업로드 크기 제한을 초과했습니다")
	}
	file, h, err := r.FormFile("file")
	if err != nil {
		return nil, "", fmt.Errorf("Excel 파일이 필요합니다")
	}
	ext := strings.ToLower(filepath.Ext(h.Filename))
	if ext != ".xlsx" {
		file.Close()
		return nil, "", fmt.Errorf(".xlsx 파일만 지원합니다")
	}
	return file, h.Filename, nil
}

var headerAliases = map[string][]string{"section": {"구분", "section"}, "item_code": {"구분 no", "구분 no.", "항목코드", "item_code"}, "title": {"보안 요건 항목", "보안요건", "점검 항목", "점검항목", "title"}, "question": {"점검항목", "점검 항목", "항목설명", "question"}, "guide": {"점검 가이드", "점검가이드", "진단방법", "guide"}, "legal_basis": {"관련 근거", "관련근거", "legal_basis"}, "example": {"현황 및 증적", "현황 및 증적 제출", "설정방법", "example"}, "severity": {"중요도", "severity"}}

func detectHeaders(rows [][]string) (int, []importColumn) {
	best, bestScore := 0, 0
	bestMap := []importColumn{}
	for i, row := range rows {
		if i > 30 {
			break
		}
		m := []importColumn{}
		score := 0
		for col, raw := range row {
			h := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(raw, "\n", " ")))
			for field, aliases := range headerAliases {
				for _, a := range aliases {
					if h == a || strings.Contains(h, a) {
						m = append(m, importColumn{Index: col, Header: raw, Field: field})
						score++
						break
					}
				}
			}
		}
		if score > bestScore {
			best, bestScore, bestMap = i, score, m
		}
	}
	return best, bestMap
}

func (s *Server) importTemplate(w http.ResponseWriter, r *http.Request) {
	file, filename, err := readWorkbookUpload(w, r)
	if err != nil {
		problem(w, 422, "IMPORT_FAILED", err.Error(), nil)
		return
	}
	defer file.Close()
	sheet := r.FormValue("sheet")
	name := valueDefault(r.FormValue("name"), sheet)
	category := strings.ToUpper(valueDefault(r.FormValue("category"), inferCategory(sheet)))
	version := valueDefault(r.FormValue("version"), extractVersion(sheet))
	publish := r.FormValue("publish") == "true"
	f, err := excelize.OpenReader(file)
	if err != nil {
		problem(w, 422, "IMPORT_FAILED", "Excel 파일을 읽을 수 없습니다.", nil)
		return
	}
	defer f.Close()
	if sheet == "" && len(f.GetSheetList()) > 0 {
		sheet = f.GetSheetList()[0]
	}
	for _, candidate := range f.GetSheetList() {
		if strings.TrimSpace(candidate) == strings.TrimSpace(sheet) {
			sheet = candidate
			break
		}
	}
	rows, err := f.GetRows(sheet)
	if err != nil {
		problem(w, 422, "IMPORT_FAILED", "선택한 시트를 찾을 수 없습니다.", map[string]any{"requested": sheet, "available": f.GetSheetList()})
		return
	}
	header, mapping := detectHeaders(rows)
	if custom := r.FormValue("mapping"); custom != "" {
		_ = json.Unmarshal([]byte(custom), &mapping)
	}
	items := parseImportRows(rows, header, mapping, category)
	if len(items) == 0 {
		problem(w, 422, "IMPORT_FAILED", "가져올 체크리스트 항목을 찾지 못했습니다.", map[string]any{"header_row": header + 1, "mapping": mapping})
		return
	}
	tid, vid := store.NewID(), store.NewID()
	tx, err := s.Store.Pool.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO checklist_templates(id,name,category,description,created_by) VALUES($1,$2,$3,$4,$5)`, tid, name, category, "Excel Import: "+filename, session(r).User.ID)
		status := "DRAFT"
		var published any
		if publish {
			status = "PUBLISHED"
			published = time.Now()
		}
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO checklist_versions(id,template_id,version,status,change_note,source_filename,created_by,published_by,published_at) VALUES($1,$2,$3,$4,'Excel Import',$5,$6,CASE WHEN $4='PUBLISHED' THEN $6 ELSE NULL END,$7)`, vid, tid, version, status, filename, session(r).User.ID, published)
		}
		sections := map[string]string{}
		for _, item := range items {
			if err != nil {
				break
			}
			secID := sections[item.Section]
			if secID == "" && item.Section != "" {
				secID = store.NewID()
				sections[item.Section] = secID
				_, err = tx.Exec(r.Context(), `INSERT INTO checklist_sections(id,version_id,name,sort_order) VALUES($1,$2,$3,$4)`, secID, vid, item.Section, len(sections))
			}
			if err == nil {
				_, err = tx.Exec(r.Context(), `INSERT INTO checklist_items(id,version_id,section_id,item_code,category,title,question,guide,legal_basis,example,severity,required,answer_type,evidence_required,sort_order) VALUES($1,$2,NULLIF($3,''),$4,$5,$6,$7,$8,$9,$10,$11,true,'YNNA',false,$12)`, store.NewID(), vid, secID, item.ItemCode, item.Category, item.Title, item.Question, item.Guide, item.LegalBasis, item.Example, item.Severity, item.SortOrder)
			}
		}
		if err == nil {
			err = tx.Commit(r.Context())
		} else {
			_ = tx.Rollback(r.Context())
		}
	}
	if err != nil {
		problem(w, 500, "IMPORT_FAILED", "템플릿을 저장하지 못했습니다.", err.Error())
		return
	}
	_ = s.Store.Audit(r.Context(), auditFrom(r, "CREATE_TEMPLATE", "TEMPLATE", tid, nil, map[string]any{"source": filename, "sheet": sheet, "items": len(items)}))
	jsonResponse(w, 201, map[string]any{"id": tid, "version_id": vid, "items": len(items), "status": map[bool]string{true: "PUBLISHED", false: "DRAFT"}[publish]})
}

// importReport explains what the parser did to the workbook, so the preview
// can be a real dry run instead of five raw rows.
type importReport struct {
	Parsed         int      `json:"parsed"`
	SkippedRows    int      `json:"skipped_rows"`
	GeneratedCodes int      `json:"generated_codes"`
	DuplicateCodes []string `json:"duplicate_codes"`
	MissingFields  []string `json:"missing_fields"`
}

func parseImportRows(rows [][]string, header int, mapping []importColumn, category string) []itemInput {
	items, _ := parseImportRowsWithReport(rows, header, mapping, category)
	return items
}

func parseImportRowsWithReport(rows [][]string, header int, mapping []importColumn, category string) ([]itemInput, importReport) {
	report := importReport{DuplicateCodes: []string{}, MissingFields: []string{}}
	items := []itemInput{}
	idx := map[string]int{}
	seenCodes := map[string]int{}
	for _, m := range mapping {
		if _, exists := idx[m.Field]; !exists {
			idx[m.Field] = m.Index
		}
	}
	for i := header + 1; i < len(rows); i++ {
		row := rows[i]
		get := func(field string) string {
			n, ok := idx[field]
			if !ok || n >= len(row) {
				return ""
			}
			return strings.TrimSpace(row[n])
		}
		code, title, question := normalizeItemCode(get("item_code")), get("title"), get("question")
		if title == "" && question != "" {
			title = truncate(question, 80)
		}
		if question == "" {
			question = title
		}
		if title == "" {
			// A row with neither a requirement nor a question is a spacer or a
			// note, not a checklist item.
			if strings.TrimSpace(strings.Join(row, "")) != "" {
				report.SkippedRows++
			}
			continue
		}
		if code == "" {
			code = fmt.Sprintf("%s-%03d", strings.ToUpper(category), i-header)
			report.GeneratedCodes++
		}
		seenCodes[code]++
		if seenCodes[code] > 1 {
			if !contains(report.DuplicateCodes, code) {
				report.DuplicateCodes = append(report.DuplicateCodes, code)
			}
			code = fmt.Sprintf("%s-DUP%d", code, seenCodes[code])
		}
		severity := normalizeSeverity(get("severity"))
		items = append(items, itemInput{Section: get("section"), ItemCode: code, Category: category, Title: title, Question: question, Guide: get("guide"), LegalBasis: get("legal_basis"), Example: get("example"), Severity: severity, Required: true, AnswerType: "YNNA", SortOrder: i - header})
	}
	report.Parsed = len(items)
	for _, field := range []string{"item_code", "title", "question", "guide", "severity"} {
		if _, mapped := idx[field]; !mapped {
			report.MissingFields = append(report.MissingFields, field)
		}
	}
	return items, report
}

func normalizeItemCode(code string) string {
	if len(code) > 10 && strings.Contains(code, ".") {
		if n, err := strconv.ParseFloat(code, 64); err == nil {
			return strconv.FormatFloat(n, 'f', -1, 64)
		}
	}
	return code
}
func normalizeSeverity(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "상", "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "중", "MEDIUM":
		return "MEDIUM"
	case "하", "LOW":
		return "LOW"
	}
	return "MEDIUM"
}
func inferCategory(sheet string) string {
	s := strings.ToLower(sheet)
	switch {
	case strings.Contains(s, "개인") || strings.Contains(s, "신용"):
		return "PRIVACY"
	case strings.Contains(s, "클라우드"):
		return "CLOUD"
	case strings.Contains(s, "docker"):
		return "DOCKER"
	case strings.Contains(s, "kubernetes"):
		return "KUBERNETES"
	default:
		return "DEVELOPMENT"
	}
}
func extractVersion(name string) string {
	upper := strings.ToUpper(name)
	if i := strings.Index(upper, "V"); i >= 0 {
		fields := strings.Fields(upper[i:])
		if len(fields) > 0 {
			return strings.Trim(fields[0], "()")
		}
	}
	return "V1.0"
}
func truncate(v string, n int) string {
	r := []rune(v)
	if len(r) <= n {
		return v
	}
	return string(r[:n]) + "…"
}
func valueDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func (s *Server) exportTemplate(w http.ResponseWriter, r *http.Request) {
	tid := r.PathValue("id")
	var name, version, vid string
	err := s.Store.Pool.QueryRow(r.Context(), `SELECT t.name,v.version,v.id FROM checklist_templates t JOIN checklist_versions v ON v.template_id=t.id WHERE t.id=$1 ORDER BY (v.status='PUBLISHED') DESC,v.created_at DESC LIMIT 1`, tid).Scan(&name, &version, &vid)
	if err != nil {
		problem(w, 404, "NOT_FOUND", "템플릿을 찾을 수 없습니다.", nil)
		return
	}
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT COALESCE(sec.name,''),i.item_code,i.title,i.question,i.guide,i.legal_basis,i.example,i.severity,i.required,i.answer_type,i.evidence_required FROM checklist_items i LEFT JOIN checklist_sections sec ON sec.id=i.section_id WHERE i.version_id=$1 ORDER BY i.sort_order`, vid)
	if err != nil {
		problem(w, 500, "EXPORT_FAILED", "템플릿을 내보내지 못했습니다.", nil)
		return
	}
	defer rows.Close()
	f := excelize.NewFile()
	defer f.Close()
	sheet := "Checklist"
	f.SetSheetName("Sheet1", sheet)
	headers := []string{"구분", "항목코드", "보안 요건 항목", "점검항목", "점검 가이드", "관련 근거", "현황 및 증적 예시", "중요도", "필수", "입력 유형", "증적 필수"}
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = f.SetCellValue(sheet, cell, h)
	}
	row := 2
	for rows.Next() {
		var vals [11]any
		if err = rows.Scan(&vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5], &vals[6], &vals[7], &vals[8], &vals[9], &vals[10]); err != nil {
			problem(w, 500, "EXPORT_FAILED", "템플릿을 내보내지 못했습니다.", nil)
			return
		}
		for i, v := range vals {
			cell, _ := excelize.CoordinatesToCellName(i+1, row)
			_ = f.SetCellValue(sheet, cell, v)
		}
		row++
	}
	_ = f.SetColWidth(sheet, "A", "K", 22)
	buf, err := f.WriteToBuffer()
	if err != nil {
		problem(w, 500, "EXPORT_FAILED", "템플릿을 내보내지 못했습니다.", nil)
		return
	}
	filename := sanitizeFilename(name + "-" + version + ".xlsx")
	w.Header().Set("Content-Disposition", `attachment; filename*=UTF-8''`+urlEncode(filename))
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	_, _ = io.Copy(w, bytes.NewReader(buf.Bytes()))
	_ = s.Store.Audit(r.Context(), auditFrom(r, "EXPORT_DATA", "TEMPLATE", tid, nil, map[string]string{"format": "xlsx"}))
}

func sanitizeFilename(v string) string {
	v = strings.Map(func(r rune) rune {
		if strings.ContainsRune(`/\\:*?"<>|`, r) || r < 32 {
			return '_'
		}
		return r
	}, v)
	return v
}
func urlEncode(v string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(v, " ", "%20"), "#", "%23"), "?", "%3F")
}

var _ = sort.Strings
var _ = strconv.Itoa

// simulateRules answers "which checklist would this service profile get?"
// without creating a review. Applicability rules were previously only
// observable after the fact, so a template administrator had no way to check
// a rule before publishing it — and a published version cannot be edited.
func (s *Server) simulateRules(w http.ResponseWriter, r *http.Request) {
	var in reviewInput
	if !decodeJSON(w, r, &in) {
		return
	}
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT t.name,v.version,v.status,i.item_code,i.category,i.title,i.severity,i.applicability_rule
                FROM checklist_items i
                JOIN checklist_versions v ON v.id=i.version_id
                JOIN checklist_templates t ON t.id=v.template_id
                WHERE t.active AND v.status='PUBLISHED'
                  AND v.id=(SELECT v2.id FROM checklist_versions v2 WHERE v2.template_id=t.id AND v2.status='PUBLISHED' ORDER BY v2.published_at DESC NULLS LAST,v2.created_at DESC LIMIT 1)
                ORDER BY t.name,i.sort_order`)
	if err != nil {
		problem(w, 500, "QUERY_FAILED", "체크리스트를 불러오지 못했습니다.", nil)
		return
	}
	defer rows.Close()

	fields := reviewFields(in)
	type outcome struct {
		Template string `json:"template"`
		Version  string `json:"version"`
		ItemCode string `json:"item_code"`
		Category string `json:"category"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
		Applied  bool   `json:"applied"`
		Reason   string `json:"reason"`
	}
	items := []outcome{}
	byTemplate := map[string]map[string]int{}
	applied, excluded := 0, 0
	for rows.Next() {
		var o outcome
		var rule []byte
		if err = rows.Scan(&o.Template, &o.Version, new(string), &o.ItemCode, &o.Category, &o.Title, &o.Severity, &rule); err != nil {
			problem(w, 500, "QUERY_FAILED", "체크리스트를 불러오지 못했습니다.", nil)
			return
		}
		switch {
		case !categoryApplies(o.Category, in):
			o.Reason = "서비스 특성상 해당 분류가 적용되지 않습니다"
		case !evaluateRule(rule, fields):
			o.Reason = "항목의 적용 규칙 조건을 만족하지 않습니다"
		default:
			o.Applied = true
			o.Reason = "적용"
		}
		if o.Applied {
			applied++
		} else {
			excluded++
		}
		if byTemplate[o.Template] == nil {
			byTemplate[o.Template] = map[string]int{}
		}
		byTemplate[o.Template]["total"]++
		if o.Applied {
			byTemplate[o.Template]["applied"]++
		}
		items = append(items, o)
	}
	if err = rows.Err(); err != nil {
		problem(w, 500, "QUERY_FAILED", "체크리스트를 불러오지 못했습니다.", nil)
		return
	}
	summary := []map[string]any{}
	for name, counts := range byTemplate {
		summary = append(summary, map[string]any{"template": name, "applied": counts["applied"], "total": counts["total"]})
	}
	sort.Slice(summary, func(i, j int) bool { return summary[i]["template"].(string) < summary[j]["template"].(string) })
	jsonResponse(w, 200, map[string]any{"applied": applied, "excluded": excluded, "profile": fields, "templates": summary, "items": items})
}
