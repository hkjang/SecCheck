import { FormEvent, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowLeft, ArrowRight, Info, ListChecks } from 'lucide-react'
import { directory, get, post, errorMessage, ApiError } from '../lib/api'
import { DirectoryUser } from '../lib/types'
import { Badge, Button, Field, PeopleField, Toggle, useToast } from '../components/ui'
import { useAuth } from '../main'

const initial = { service_name: '', description: '', service_type: 'INTERNAL', change_type: 'NEW', builder_id: '', developer_id: '', operator_id: '', department: '', reviewer_id: '', approver_id: '', planned_open_date: '', exposure: 'INTERNAL', has_admin_page: false, processes_personal_data: false, processes_credit_data: false, external_customer_service: false, uses_cloud: false, uses_docker: false, uses_kubernetes: false, external_integration: false, internet_access: false, business_criticality: 'MEDIUM', manual_rule_override_reason: '' }

type PreviewItem = { template: string; item_code: string; title: string; severity: string; applied: boolean; evidence_required: boolean; required: boolean; guide?: string }

export default function NewReview() {
  const { user } = useAuth(); const navigate = useNavigate(); const toast = useToast()
  const [form, setForm] = useState(initial)
  const [users, setUsers] = useState<DirectoryUser[]>([])
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState(false)
  useEffect(() => { directory<DirectoryUser>().then(list => { setUsers(list); setForm(v => ({ ...v, builder_id: user.id, developer_id: user.id, department: user.department })) }) }, [user])
  const set = <K extends keyof typeof form>(key: K, value: typeof form[K]) => setForm(v => ({ ...v, [key]: value }))
  const submit = async (e: FormEvent) => { e.preventDefault(); setBusy(true); setErrors({}); try { const out = await post<{ id: string; assigned_items: number }>('/api/v1/review-requests', form); toast.push(`${out.assigned_items}개 체크리스트 항목이 배정되었습니다.`); navigate(`/reviews/${out.id}`) } catch (e) { if (e instanceof ApiError && e.details) setErrors(e.details as Record<string, string>); toast.push(errorMessage(e), 'error') } finally { setBusy(false) } }
  // Nine characteristic toggles decide the whole checklist, and until now
  // their effect was invisible until after the review existed.
  const [preview, setPreview] = useState<{ applied: number; excluded: number; templates: { template: string; applied: number; total: number }[]; items?: PreviewItem[] }>()
  // Being told that forty-two items are coming is not the same as being able
  // to read them: the point of asking before the review exists is to gather
  // the evidence first.
  const [showItems, setShowItems] = useState(false)
  useEffect(() => {
    const timer = window.setTimeout(() => {
      post<typeof preview>('/api/v1/templates/rule-simulation', { ...form, service_name: form.service_name || '미리보기', description: form.description || '미리보기', department: form.department || '미리보기', builder_id: '', developer_id: '', operator_id: '', reviewer_id: '', approver_id: '', planned_open_date: '' })
        .then(setPreview).catch(() => setPreview(undefined))
    }, 300)
    return () => clearTimeout(timer)
  }, [form.service_type, form.change_type, form.exposure, form.business_criticality, form.has_admin_page, form.processes_personal_data, form.processes_credit_data, form.external_customer_service, form.uses_cloud, form.uses_docker, form.uses_kubernetes, form.external_integration, form.internet_access])
  return <div className="page"><div className="page-header"><div><h1 className="page-title">신규 보안성 심의 요청</h1><p className="page-description">서비스 특성을 정확히 입력하면 Rule Engine이 게시된 템플릿에서 항목을 스냅샷으로 배정합니다.</p></div><Button onClick={() => navigate(-1)}><ArrowLeft size={14} /> 돌아가기</Button></div>
    <form onSubmit={submit}><section className="card"><div className="card-header"><h2>서비스 기본정보</h2></div><div className="card-body"><div className="form-grid"><Field label="서비스명" required error={errors.service_name}><input className="input" value={form.service_name} onChange={e => set('service_name', e.target.value)} /></Field><Field label="담당 부서" required error={errors.department}><input className="input" value={form.department} onChange={e => set('department', e.target.value)} /></Field><Field label="서비스 설명" required error={errors.description} className="span-2"><textarea className="textarea" value={form.description} onChange={e => set('description', e.target.value)} /></Field><Field label="서비스 유형" required><select className="select" value={form.service_type} onChange={e => set('service_type', e.target.value)}><option value="INTERNAL">대내 서비스</option><option value="EXTERNAL">대외 서비스</option><option value="ADMIN">관리자 서비스</option><option value="BATCH">배치/백엔드</option></select></Field><Field label="신규·변경 구분" required><select className="select" value={form.change_type} onChange={e => set('change_type', e.target.value)}><option value="NEW">신규</option><option value="CHANGE">변경</option><option value="REVIEW">재심의</option></select></Field><Field label="구축 담당자" required><PeopleField value={form.builder_id} people={users} onChange={id => set('builder_id', id)} emptyLabel="선택" withDepartment /></Field><Field label="개발 담당자" required><PeopleField value={form.developer_id} people={users} onChange={id => set('developer_id', id)} emptyLabel="선택" withDepartment /></Field><Field label="운영 담당자"><PeopleField value={form.operator_id} people={users} onChange={id => set('operator_id', id)} emptyLabel="선택 안 함" withDepartment /></Field><Field label="오픈 예정일"><input type="date" className="input" value={form.planned_open_date} onChange={e => set('planned_open_date', e.target.value)} /></Field><Field label="대내·대외 여부" required><select className="select" value={form.exposure} onChange={e => set('exposure', e.target.value)}><option value="INTERNAL">대내</option><option value="EXTERNAL">대외</option><option value="BOTH">대내·대외</option></select></Field><Field label="업무 중요도"><select className="select" value={form.business_criticality} onChange={e => set('business_criticality', e.target.value)}><option value="LOW">낮음</option><option value="MEDIUM">보통</option><option value="HIGH">높음</option><option value="CRITICAL">핵심</option></select></Field></div></div></section>
      <section className="card" data-sx="sx-030"><div className="card-header"><h2>적용 조건</h2><span className="subtle"><Info size={13} /> 체크리스트 자동 배정 입력값</span></div><div className="card-body"><div className="grid two"><Toggle label="관리자 페이지 존재" value={form.has_admin_page} onChange={v => set('has_admin_page', v)} /><Toggle label="개인정보 처리" value={form.processes_personal_data} onChange={v => set('processes_personal_data', v)} /><Toggle label="개인신용정보 처리" value={form.processes_credit_data} onChange={v => set('processes_credit_data', v)} /><Toggle label="외부 고객 서비스" value={form.external_customer_service} onChange={v => set('external_customer_service', v)} /><Toggle label="클라우드 사용" value={form.uses_cloud} onChange={v => set('uses_cloud', v)} /><Toggle label="Docker 사용" value={form.uses_docker} onChange={v => set('uses_docker', v)} /><Toggle label="Kubernetes 사용" value={form.uses_kubernetes} onChange={v => set('uses_kubernetes', v)} /><Toggle label="외부기관 연계" value={form.external_integration} onChange={v => set('external_integration', v)} /><Toggle label="인터넷 통신" value={form.internet_access} onChange={v => set('internet_access', v)} /></div></div></section>
      {preview && <section className="card"><div className="card-header"><h2><ListChecks size={17} /> 배정될 체크리스트 미리보기</h2><Badge tone={preview.applied ? 'blue' : 'red'}>{preview.applied}개 항목</Badge></div><div className="card-body">
        {preview.applied ? <><p className="subtle">위 특성으로 생성하면 아래 템플릿에서 항목이 배정됩니다. 특성을 바꾸면 즉시 다시 계산됩니다.</p>
          <div className="table-wrap"><table><caption className="sr-only">템플릿별 배정 예정 항목</caption><thead><tr><th scope="col">템플릿</th><th scope="col">배정 / 전체</th></tr></thead><tbody>{preview.templates.filter(t => t.applied > 0).map(t => <tr key={t.template}><td>{t.template}</td><td><Badge tone="green">{t.applied} / {t.total}</Badge></td></tr>)}</tbody></table></div>
          {(() => { const applied = (preview.items || []).filter(i => i.applied); const files = applied.filter(i => i.evidence_required); return <>
            <div data-sx="sx-010"><Button small type="button" onClick={() => setShowItems(v => !v)}>{showItems ? '항목 목록 접기' : `배정될 항목 ${applied.length}개 보기`}</Button>
              {files.length > 0 && <span className="subtle"> · 이 중 {files.length}개는 증적 파일이 필요합니다. 미리 준비하세요.</span>}</div>
            {showItems && <div className="table-wrap"><table><caption className="sr-only">배정될 체크리스트 항목</caption>
              <thead><tr><th scope="col">항목코드</th><th scope="col">보안요건</th><th scope="col">중요도</th><th scope="col">증적</th></tr></thead>
              <tbody>{applied.map((item, i) => <tr key={`${item.template}-${item.item_code}-${i}`}>
                <td><code>{item.item_code}</code><div className="subtle">{item.template}</div></td>
                <td>{item.title}{item.guide ? <div className="subtle">{item.guide}</div> : null}</td>
                <td>{item.severity}</td>
                <td>{item.evidence_required ? <Badge tone="amber">필요</Badge> : <span className="subtle">-</span>}</td>
              </tr>)}</tbody></table></div>}
          </> })()}</>
          : <div className="guide-block">현재 특성으로는 배정될 항목이 없습니다. 서비스 특성을 확인하거나 체크리스트 관리자에게 문의하세요.</div>}
      </div></section>}
      <div data-sx="sx-010"><Button variant="primary" disabled={busy}>{busy ? '생성 중…' : <>심의 생성 및 항목 배정 <ArrowRight size={15} /></>}</Button></div></form></div>
}
