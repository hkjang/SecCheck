import { ChangeEvent, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { AlertTriangle, ArrowLeft, Check, CheckCircle2, CheckSquare, ChevronDown, ChevronRight, ChevronUp, Copy, Download, FileCheck2, FilePlus2, Filter, ListChecks, MessageSquareWarning, Paperclip, Play, RefreshCw, History, Save, Search, Send, ShieldCheck, SlidersHorizontal, Trash2, UserRound, Upload, ZoomIn } from 'lucide-react'
import { api, del, errorMessage, get, post, put, upload, ApiError } from '../lib/api'
import { ChangeRequest, ChecklistItem, DirectoryUser, Review } from '../lib/types'
import { Badge, Button, Empty, Field, formatBytes, formatDate, LoadFailed, Loading, Modal, StatusBadge, Toggle, useDownload, useToast } from '../components/ui'
import { useAuth } from '../main'

type ResponseDraft = { answer: unknown; applicability: string; self_assessment: string; current_state: string; na_reason: string; action_plan: string; assigned_to: string }
const responseFrom = (item: ChecklistItem): ResponseDraft => ({ answer: item.response.answer_json || {}, applicability: String(item.response.applicability || ''), self_assessment: String(item.response.self_assessment || ''), current_state: String(item.response.current_state || ''), na_reason: String(item.response.na_reason || ''), action_plan: String(item.response.action_plan || ''), assigned_to: String(item.response.assigned_to || '') })

export default function ReviewDetail() {
  const save = useDownload()
  const { id = '' } = useParams(); const { user } = useAuth(); const toast = useToast(); const navigate = useNavigate()
  const [review, setReview] = useState<Review>(); const [items, setItems] = useState<ChecklistItem[]>(); const [selected, setSelected] = useState<string>(''); const [open, setOpen] = useState<Set<string>>(new Set()); const [query, setQuery] = useState(''); const [filter, setFilter] = useState('ALL'); const [validation, setValidation] = useState<Record<string, unknown>[] | null>(null); const [dialog, setDialog] = useState<'complete' | 'approval' | 'reject' | null>(null); const [ruleOpen, setRuleOpen] = useState(false); const [busy, setBusy] = useState(false); const [picked, setPicked] = useState<Set<string>>(new Set()); const [bulkOpen, setBulkOpen] = useState(false); const [historyOpen, setHistoryOpen] = useState(false)
  const reviewer = user.roles.includes('SECURITY_REVIEWER'); const approver = user.roles.includes('APPROVER')
  const load = async () => { const [r, i] = await Promise.all([get<Review>(`/api/v1/review-requests/${id}`), get<ChecklistItem[]>(`/api/v1/review-requests/${id}/items`)]); setReview(r); setItems(i); if (!selected && i[0]) setSelected(i[0].id) }
  const [failed, setFailed] = useState<unknown>()
  useEffect(() => { setFailed(undefined); load().catch(setFailed) }, [id])
  const filtered = useMemo(() => (items || []).filter(item => { const hit = !query || `${item.item_code} ${item.title} ${item.question}`.toLowerCase().includes(query.toLowerCase()); if (!hit) return false; if (filter === 'MISSING') return !item.response.applicability; if (filter === 'NA') return item.response.applicability === 'N/A'; if (filter === 'EVIDENCE') return item.evidence_required && !item.evidences.length; if (filter === 'CHANGE') return item.change_requests.some(c => c.status !== 'VERIFIED'); if (filter === 'MINE') return item.response.assigned_to === user.id; return true }), [items, query, filter, user.id])
  const sections = useMemo(() => Array.from(new Set((items || []).map(x => `${x.template_name} · ${x.section || '일반'}`))), [items])
  // Showing how much is left per filter turns the dropdown into a to-do list
  // instead of a blind switch.
  const counts = useMemo(() => { const all = items || []; return { ALL: all.length, MISSING: all.filter(x => !x.response.applicability).length, NA: all.filter(x => x.response.applicability === 'N/A').length, EVIDENCE: all.filter(x => x.evidence_required && !x.evidences.length).length, CHANGE: all.filter(x => x.change_requests.some(c => c.status !== 'VERIFIED')).length, MINE: all.filter(x => x.response.assigned_to === user.id).length } }, [items, user.id])
  const [people, setPeople] = useState<DirectoryUser[]>([])
  useEffect(() => { get<DirectoryUser[]>('/api/v1/users/directory').then(setPeople).catch(() => undefined) }, [])
  const nameOf = (id: unknown) => people.find(p => p.id === String(id || ''))?.display_name || ''
  // Jumping straight to a flagged item is the point of the submission report;
  // the active filter is cleared first so the target is never hidden.
  const focusItem = (code: string) => { const target = (items || []).find(x => x.item_code === code); if (!target) return; setValidation(null); setFilter('ALL'); setQuery(''); setSelected(target.id); setOpen(v => new Set(v).add(target.id)); window.setTimeout(() => document.getElementById(`item-${target.id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 60) }
  const current = items?.find(x => x.id === selected)
  // A reviewer works through every item in turn, and until now that meant
  // finding and clicking each one in a list of a few hundred.
  const position = filtered.findIndex(x => x.id === selected)
  const step = (delta: number) => {
    if (!filtered.length) return
    const next = filtered[position < 0 ? 0 : Math.min(filtered.length - 1, Math.max(0, position + delta))]
    if (!next) return
    setSelected(next.id)
    setOpen(v => new Set(v).add(next.id))
    document.getElementById(`item-${next.id}`)?.scrollIntoView({ block: 'nearest' })
  }
  // Alt is required so the shortcut cannot fire while somebody is typing an
  // answer, which is most of what happens on this screen.
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if (!e.altKey || (e.key !== 'ArrowDown' && e.key !== 'ArrowUp')) return
      e.preventDefault()
      step(e.key === 'ArrowDown' ? 1 : -1)
    }
    window.addEventListener('keydown', key)
    return () => window.removeEventListener('keydown', key)
    // Deliberately re-registered every render: the handler closes over the
    // current filter and position, and an empty dependency list would freeze
    // it at the first item.
  })
  const togglePick = (id: string) => setPicked(v => { const n = new Set(v); n.has(id) ? n.delete(id) : n.add(id); return n })
  const action = async (path: string, data?: unknown) => { setBusy(true); try { const out = await post<{ status: string }>(`/api/v1/review-requests/${id}/${path}`, data); toast.push(`상태가 ${out.status}(으)로 변경되었습니다.`); setDialog(null); await load() } catch (e) { if (e instanceof ApiError && e.code === 'SUBMISSION_INCOMPLETE') setValidation(e.details as Record<string, unknown>[]); else toast.push(errorMessage(e), 'error') } finally { setBusy(false) } }
  const verifyChange=async(changeID:string)=>{try{await api(`/api/v1/change-requests/${changeID}`,{method:'PATCH',body:JSON.stringify({status:'VERIFIED',answer:''})});toast.push('보완 조치를 검증 완료했습니다.');await load()}catch(e){toast.push(errorMessage(e),'error')}}
  if (failed) return <LoadFailed error={failed} onRetry={() => { setFailed(undefined); load().catch(setFailed) }} />
  if (!review || !items) return <Loading />
  const editable = ['DRAFT', 'CHANGE_REQUESTED'].includes(review.status)
  const judging = reviewer && review.status === 'REVIEWING'
  const selecting = editable || judging
  const progress = review.progress || { total: items.length, answered: items.filter(x => x.response.applicability).length, evidence: 0 }; const percent = progress.total ? Math.round(progress.answered / progress.total * 100) : 0; const results=(review.result_summary||{}) as Record<string,number>
  const copyReview = async () => {
    try {
      const out = await post<{ id: string; carried: number; total: number; new_items: number; dropped_items: number }>(`/api/v1/review-requests/${id}/copy`)
      // The new review is built from today's published templates, so say what
      // survived rather than letting the requester find out by scrolling.
      const notes = [`${out.carried}/${out.total}개 항목의 답변을 복사했습니다.`]
      if (out.new_items) notes.push(`신설 항목 ${out.new_items}개는 새로 작성해야 합니다.`)
      if (out.dropped_items) notes.push(`이전 심의의 ${out.dropped_items}개 항목은 현재 템플릿에 없어 제외되었습니다.`)
      toast.push(notes.join(' '))
      navigate(`/reviews/${out.id}`)
    } catch (e) { toast.push(errorMessage(e), 'error') }
  }
  return <div className="page" data-sx="sx-038"><div className="page-header"><div><Button variant="ghost" small onClick={() => navigate(-1)}><ArrowLeft size={14} /> 목록</Button><h1 className="page-title" data-sx="sx-035">{review.service_name}</h1><p className="page-description">{review.review_number} · {review.department} · {review.service_type}</p></div><div className="header-actions"><StatusBadge status={review.status} /><Button onClick={() => setHistoryOpen(true)}><History size={14} /> 이력</Button>{user.roles.includes('REQUESTER') && <Button onClick={copyReview}><Copy size={14}/> 재심의 복사</Button>}{review.status === 'DRAFT' && user.roles.includes('TEMPLATE_ADMIN') && <Button onClick={() => setRuleOpen(true)}><SlidersHorizontal size={14}/> 자동 배정 조정</Button>}{review.requester_id===user.id&&['DRAFT','CHANGE_REQUESTED'].includes(review.status)&&<Button variant="danger" onClick={()=>{if(confirm('이 심의를 취소할까요?'))action('cancel')}}>요청 취소</Button>}{['DRAFT', 'CHANGE_REQUESTED'].includes(review.status) && <Button variant="primary" disabled={busy} onClick={() => action('submit')}><Send size={14} /> {review.status === 'DRAFT' ? '제출' : '재제출'}</Button>}{reviewer && ['SUBMITTED', 'RESUBMITTED'].includes(review.status) && <Button variant="primary" disabled={busy} onClick={() => action('begin-review')}><Play size={14} /> 검토 시작</Button>}{reviewer && review.status === 'REVIEWING' && <><Button onClick={() => setDialog('complete')}><CheckCircle2 size={14} /> 검토 완료</Button></>}{reviewer&&review.reviewer_id===user.id&&['APPROVED','REJECTED'].includes(review.status)&&<Button onClick={()=>action('close')}>심의 종료</Button>}{approver && review.status === 'APPROVAL_PENDING' && <><Button variant="danger" onClick={() => setDialog('reject')}>반려</Button><Button variant="success" onClick={() => setDialog('approval')}><ShieldCheck size={14} /> 최종 승인</Button></>}</div></div>
    <div className="card" data-sx="sx-027"><div className="card-body review-summary-grid"><div><span className="subtle">작성 진행률</span><div data-sx="sx-020">{percent}% <span className="subtle">({progress.answered}/{progress.total})</span></div></div><div><div className="progress"><progress value={percent} max={100}>{percent}%</progress></div></div><div><span className="subtle">검토 집계</span><div data-sx="sx-037"><Badge tone="green">적합 {results.compliant||0}</Badge><Badge tone="amber">조건부 {results.conditional||0}</Badge><Badge tone="red">미흡·부적합 {(results.insufficient||0)+(results.non_compliant||0)}</Badge><Badge>N/A {results.na||0}</Badge></div></div><div className="header-actions"><TemplateVersions review={review} /><Button small onClick={() => save(`/api/v1/review-requests/${id}/export/xlsx`)}><Download size={13} /> Excel</Button><Button small onClick={() => save(`/api/v1/review-requests/${id}/export/pdf`)}><Download size={13} /> PDF</Button><Button small onClick={() => save(`/api/v1/review-requests/${id}/export/zip`)}><Download size={13} /> ZIP</Button></div></div></div>
    <div className="toolbar"><div className="search-box"><Search /><input className="input" placeholder="항목코드, 보안요건, 질문 검색" value={query} onChange={e => setQuery(e.target.value)} /></div><Filter size={16} color="#6d7a8e" /><select className="select" data-sx="sx-051" value={filter} onChange={e => setFilter(e.target.value)}><option value="ALL">전체 항목 ({counts.ALL})</option><option value="MISSING">미작성 ({counts.MISSING})</option><option value="NA">N/A ({counts.NA})</option><option value="EVIDENCE">증적 누락 ({counts.EVIDENCE})</option><option value="CHANGE">보완 요청 ({counts.CHANGE})</option><option value="MINE">내 담당 항목 ({counts.MINE})</option></select></div>
    <div className="review-layout"><aside className="card section-nav"><div className="card-header"><h3>섹션 이동</h3><Badge>{items.length}</Badge></div><div className="card-body" data-sx="sx-044">{sections.map(section => <button key={section} onClick={() => document.getElementById(`section-${sections.indexOf(section)}`)?.scrollIntoView({ behavior: 'smooth' })}><span>{section}</span><ChevronRight size={13} /></button>)}</div></aside>
      <section className="checklist-list">{filtered.length ? filtered.map((item, index) => { const sectionName = `${item.template_name} · ${item.section || '일반'}`; const sectionIndex = sections.indexOf(sectionName); const previous = index > 0 ? `${filtered[index - 1].template_name} · ${filtered[index - 1].section || '일반'}` : ''; const expanded = open.has(item.id); return <div key={item.id}>{sectionName !== previous && <div id={`section-${sectionIndex}`} data-sx="sx-025">{sectionName} <Badge tone="blue">{item.template_version}</Badge></div>}<article className="checklist-card" id={`item-${item.id}`}><div className="checklist-summary" onClick={() => { setSelected(item.id); setOpen(v => { const n = new Set(v); n.has(item.id) ? n.delete(item.id) : n.add(item.id); return n }) }}><div>{selecting && <input type="checkbox" className="item-select" aria-label={`${item.item_code} 선택`} checked={picked.has(item.id)} onClick={e => e.stopPropagation()} onChange={() => togglePick(item.id)} />}<span className="item-code">{item.item_code}</span> <span className={`badge severity-${item.severity}`}>{item.severity}</span>{item.evidence_required && <Badge tone="amber">증적 필수</Badge>}{item.response.assigned_to ? <Badge tone={item.response.assigned_to === user.id ? 'blue' : 'purple'}><UserRound size={11} /> {nameOf(item.response.assigned_to) || '담당자'}</Badge> : null}<div className="item-title">{item.title}</div><div className="item-question">{item.question}</div></div><div>{item.response.applicability ? <Badge tone={item.response.applicability === 'N/A' ? 'amber' : 'green'}>{String(item.response.applicability)}</Badge> : <Badge>미작성</Badge>} {expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</div></div>{expanded && <ItemEditor review={review} item={item} reviewer={reviewer} people={people} onSaved={load} onSelect={() => setSelected(item.id)} />}</article></div> }) : <Empty title="필터 조건에 맞는 항목이 없습니다." />}</section>
      <aside className="card detail-panel"><div className="card-header"><h3>항목 상세</h3>{current && <Badge tone="blue">{current.item_code}</Badge>}{filtered.length > 0 && <div className="header-actions"><span className="subtle">{position >= 0 ? position + 1 : '-'} / {filtered.length}</span><Button small aria-label="이전 항목 (Alt+위쪽 화살표)" title="이전 항목 (Alt+↑)" disabled={position <= 0} onClick={() => step(-1)}><ChevronUp size={13} /></Button><Button small aria-label="다음 항목 (Alt+아래쪽 화살표)" title="다음 항목 (Alt+↓)" disabled={position < 0 || position >= filtered.length - 1} onClick={() => step(1)}><ChevronDown size={13} /></Button></div>}</div><div className="card-body">{current ? <><strong>{current.title}</strong><p className="subtle" data-sx="sx-022">{current.question}</p><h4>점검 가이드</h4><div className="guide-block">{current.guide || '등록된 가이드가 없습니다.'}</div>{current.legal_basis && <><h4>관련 근거</h4><p className="subtle" data-sx="sx-049">{current.legal_basis}</p></>}{current.example && <><h4>작성 예시</h4><div className="guide-block">{current.example}</div></>}<h4>증적 ({current.evidences.length})</h4>{current.evidences.map(e => <div className="evidence-item" key={e.id}><button type="button" className="table-link" onClick={() => save(`/api/v1/evidences/${e.id}/download`)}><Paperclip size={13} /> {e.original_filename}</button><div className="subtle">{formatBytes(e.size_bytes)} · v{e.current_version} <ScanBadge status={e.scan_status} detail={String(e.scan_detail || '')} /></div><EvidencePreview evidence={e} /></div>)}<h4>보완 요청</h4>{current.change_requests.length ? current.change_requests.map(c => <div className="change-item" key={c.id}><StatusBadge status={c.status} /><p>{c.reason}</p>{c.answer&&<div className="guide-block">{c.answer}</div>}{c.due_date && <div className="subtle">기한 {formatDate(c.due_date)}</div>}{reviewer&&review.status==='REVIEWING'&&c.status==='DONE'&&<Button small variant="primary" onClick={()=>verifyChange(c.id)}><Check size={13}/> 조치 검증</Button>}</div>) : <p className="subtle">보완 요청이 없습니다.</p>}<CommentBox reviewID={review.id} item={current} onSaved={load} /></> : <Empty title="항목을 선택하세요." />}</div></aside></div>
    {selecting && picked.size > 0 && <div className="bulk-bar" role="region" aria-label="선택한 항목 일괄 작업"><CheckSquare size={16} /><strong>{picked.size}개 항목 선택됨</strong><Button small onClick={() => setPicked(new Set(filtered.map(x => x.id)))}>보이는 항목 모두</Button><Button small onClick={() => setPicked(new Set())}>선택 해제</Button><Button small variant="primary" onClick={() => setBulkOpen(true)}><ListChecks size={13} /> {judging ? '일괄 판정' : '일괄 처리'}</Button></div>}
    {historyOpen && <HistoryModal reviewID={id} onClose={() => setHistoryOpen(false)} />}
    {bulkOpen && judging && <BulkReviewModal reviewID={id} itemIDs={Array.from(picked)} count={picked.size} onClose={() => setBulkOpen(false)} onSaved={async () => { setBulkOpen(false); setPicked(new Set()); await load() }} />}
    {bulkOpen && !judging && <BulkModal reviewID={id} itemIDs={Array.from(picked)} count={picked.size} people={people} onClose={() => setBulkOpen(false)} onSaved={async () => { setBulkOpen(false); setPicked(new Set()); await load() }} />}
    {validation && <Modal title="제출 전 확인이 필요합니다" onClose={() => setValidation(null)} footer={<Button variant="primary" onClick={() => setValidation(null)}>확인</Button>}><p className="subtle">서버 검증에서 {validation.length}개 항목의 누락이 발견되었습니다. 항목을 누르면 해당 위치로 이동합니다.</p>{validation.map((issue, i) => <div className="change-item" key={i}><button className="link-button" onClick={() => focusItem(String(issue.item_code))}><strong>{String(issue.item_code)} {String(issue.title)}</strong></button><ul>{(issue.reasons as string[]).map(x => <li key={x}>{x}</li>)}</ul></div>)}</Modal>}
    {dialog && <DecisionModal kind={dialog} busy={busy} onClose={() => setDialog(null)} onSubmit={(data) => dialog === 'complete' ? action('complete-review', data) : action(dialog === 'approval' ? 'approve' : 'reject', data)} />}
    {ruleOpen && <RuleOverrideModal reviewID={id} onClose={() => setRuleOpen(false)} onSaved={load} />}
  </div>
}

// The snapshot never moves, which is the point — but a reviewer comparing this
// review against today's checklist needs to know they are looking at an older
// edition rather than assume they are not.
function TemplateVersions({ review }: { review: Review }) {
  const versions = (review.template_versions || []) as { template_name: string; snapshot_version: string; current_version: string; outdated: boolean }[]
  if (!versions.length) return null
  const stale = versions.filter(v => v.outdated)
  if (!stale.length) return <Badge tone="green">최신 체크리스트 기준</Badge>
  return <span title={stale.map(v => `${v.template_name}: ${v.snapshot_version} → ${v.current_version}`).join('\n')}>
    <Badge tone="amber">이전 체크리스트 기준 {stale.length}건</Badge>
  </span>
}

// The audit log already recorded everything that happened to a review, but
// only administrators could look at it, so the people doing the work could not
// answer when a change request arrived or why a review came back.
function HistoryModal({ reviewID, onClose }: { reviewID: string; onClose: () => void }) {
  const toast = useToast()
  const [page, setPage] = useState<{ items: Record<string, unknown>[]; total: number; has_more: boolean }>()
  const [limit, setLimit] = useState(50)
  useEffect(() => { get<{ items: Record<string, unknown>[]; total: number; has_more: boolean }>(`/api/v1/review-requests/${reviewID}/history?limit=${limit}`).then(setPage).catch(e => toast.push(errorMessage(e), 'error')) }, [reviewID, limit])
  return <Modal title="심의 이력" onClose={onClose} footer={<>{page?.has_more && <Button onClick={() => setLimit(limit + 50)}>더 보기</Button>}<Button variant="primary" onClick={onClose}>닫기</Button></>}>
    {!page ? <Loading /> : page.items.length ? <>
      <p className="subtle">전체 {page.total}건 중 최근 {page.items.length}건. 감사로그에서 이 심의와 관련된 기록만 추린 것입니다.</p>
      <div className="table-wrap"><table><caption className="sr-only">심의 이력</caption>
        <thead><tr><th scope="col">시각</th><th scope="col">행위</th><th scope="col">수행자</th><th scope="col">대상</th></tr></thead>
        <tbody>{page.items.map((e, i) => <tr key={i}><td>{formatDate(e.timestamp, true)}</td><td><Badge tone={e.result === 'SUCCESS' ? 'blue' : 'red'}>{String(e.event_label || e.event_type)}</Badge></td><td>{String(e.user_name || '-')}</td><td className="subtle">{String(e.item_code || e.target_type || '')}</td></tr>)}</tbody>
      </table></div>
    </> : <Empty title="기록된 이력이 없습니다." />}
  </Modal>
}

// Scanning happens in the background now, so the checklist has to say where a
// file stands rather than implying every upload is already cleared.
const previewable = (mime: string) => /^image\/(png|jpeg|gif|webp)$/.test(mime)

// Evidence is encrypted at rest and served only to authorised sessions, so a
// preview cannot be a plain <img src>. The file is fetched with the session
// and shown from an object URL, which the CSP allows.
function EvidencePreview({ evidence }: { evidence: ChecklistItem['evidences'][number] }) {
  const save = useDownload()
  const [url, setUrl] = useState('')
  const [error, setError] = useState('')
  const [open, setOpen] = useState(false)
  useEffect(() => {
    if (!open || url || error) return
    let revoked = false
    let objectURL = ''
    fetch(`/api/v1/evidences/${evidence.id}/download`, { credentials: 'same-origin' })
      .then(res => res.ok ? res.blob() : Promise.reject(new Error(res.status === 409 ? '악성코드 검사가 끝나지 않았습니다.' : '증적을 불러오지 못했습니다.')))
      .then(blob => { if (revoked) return; objectURL = URL.createObjectURL(blob); setUrl(objectURL) })
      .catch(e => setError(errorMessage(e)))
    return () => { revoked = true; if (objectURL) URL.revokeObjectURL(objectURL) }
  }, [open, evidence.id, url, error])
  useEffect(() => () => { if (url) URL.revokeObjectURL(url) }, [url])
  if (!previewable(String(evidence.mime_type || ''))) return null
  return <>
    <Button small onClick={() => setOpen(true)}><ZoomIn size={12} /> 미리보기</Button>
    {open && <Modal title={evidence.original_filename} onClose={() => setOpen(false)} footer={<><Button onClick={() => save(`/api/v1/evidences/${evidence.id}/download`)}><Download size={14} /> 원본 내려받기</Button><Button variant="primary" onClick={() => setOpen(false)}>닫기</Button></>}>
      {error ? <div className="guide-block">{error}</div> : url ? <img src={url} alt={evidence.original_filename} className="evidence-preview" /> : <Loading />}
      <p className="subtle">{formatBytes(evidence.size_bytes)} · v{evidence.current_version} · SHA-256 {String(evidence.sha256 || '').slice(0, 16)}…</p>
    </Modal>}
  </>
}

function ScanBadge({ status, detail }: { status: string; detail?: string }) {
  if (status === 'CLEAN') return <Badge tone="green">검사 완료</Badge>
  if (status === 'SKIPPED') return <Badge>검사 안 함</Badge>
  if (status === 'PENDING') return <Badge tone="amber">검사 중</Badge>
  // The clamd verdict explains why a file was blocked, which the badge alone
  // cannot.
  return <span title={detail || undefined}><Badge tone="red">{status === 'INFECTED' ? '악성코드 탐지' : '검사 실패'}</Badge>{detail ? <div className="subtle">{detail}</div> : null}</span>
}

// A conflict is shown rather than resolved automatically: the two versions are
// both somebody's work, so the person at the keyboard decides.
function ConflictModal({ conflict, onClose, onReload, onOverwrite }: { conflict: Record<string, unknown>; onClose: () => void; onReload: () => Promise<void>; onOverwrite: () => Promise<void> }) {
  const rows: [string, unknown][] = [['적용 여부', conflict.applicability], ['자체 판단', conflict.self_assessment], ['현황 및 증적', conflict.current_state], ['N/A 사유', conflict.na_reason], ['조치 계획', conflict.action_plan]]
  return <Modal title="다른 사용자가 먼저 저장했습니다" onClose={onClose} footer={<><Button onClick={onReload}>최신 내용 불러오기</Button><Button variant="danger" onClick={onOverwrite}>내 내용으로 덮어쓰기</Button></>}>
    <div className="guide-block">{String(conflict.updated_by || '다른 사용자')}님이 {formatDate(conflict.updated_at, true)}에 이 항목을 저장했습니다. 아래가 현재 저장된 내용입니다.</div>
    <div className="table-wrap"><table><tbody>{rows.filter(([, v]) => String(v || '')).map(([label, value]) => <tr key={label}><th>{label}</th><td>{String(value)}</td></tr>)}</tbody></table></div>
    <p className="subtle">`최신 내용 불러오기`를 누르면 작성 중이던 입력은 사라집니다. 덮어쓰면 위 내용이 내 입력으로 대체됩니다.</p>
  </Modal>
}

// Shared so the bulk dialog cannot offer a verdict the item editor does not.
const resultLabels: Record<string, string> = { COMPLIANT: '적합', CONDITIONAL: '조건부 적합', INSUFFICIENT: '미흡', NON_COMPLIANT: '부적합', NA_ACCEPTED: 'N/A 인정', RECHECK: '재확인' }

// The reviewer's counterpart to BulkModal. A long run of the same verdict is
// what makes going through a checklist take an afternoon.
function BulkReviewModal({ reviewID, itemIDs, count, onClose, onSaved }: { reviewID: string; itemIDs: string[]; count: number; onClose: () => void; onSaved: () => Promise<void> }) {
  const toast = useToast()
  const [form, setForm] = useState({ result: 'COMPLIANT', final_applicability: '', evidence_adequacy: '', opinion: '', overwrite: false })
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    setBusy(true)
    try {
      const out = await post<{ applied: number; skipped: number }>(`/api/v1/review-requests/${reviewID}/review-results/bulk`, { ...form, item_ids: itemIDs })
      toast.push(out.skipped ? `${out.applied}개 항목을 판정했습니다. 이미 판정된 ${out.skipped}개는 건너뛰었습니다.` : `${out.applied}개 항목을 판정했습니다.`)
      await onSaved()
    } catch (e) { toast.push(errorMessage(e), 'error') } finally { setBusy(false) }
  }
  return <Modal title={`선택한 ${count}개 항목 일괄 판정`} onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant="primary" disabled={busy} onClick={submit}>판정 적용</Button></>}>
    <div className="guide-block">같은 판정이 반복되는 항목을 한 번에 처리합니다. 결과는 감사로그에 일괄 판정으로 기록되며 개별 항목에서 다시 수정할 수 있습니다.</div>
    <div className="form-grid">
      <Field label="검토 결과" required><select className="select" value={form.result} onChange={e => setForm(v => ({ ...v, result: e.target.value }))}>{Object.entries(resultLabels).map(([code, label]) => <option key={code} value={code}>{label}</option>)}</select></Field>
      <Field label="최종 적용 여부" help="비우면 작성자 판단 유지"><select className="select" value={form.final_applicability} onChange={e => setForm(v => ({ ...v, final_applicability: e.target.value }))}><option value="">유지</option><option value="Y">Y</option><option value="N">N</option><option value="N/A">N/A</option></select></Field>
      <Field label="증적 충분성"><input className="input" value={form.evidence_adequacy} onChange={e => setForm(v => ({ ...v, evidence_adequacy: e.target.value }))} /></Field>
      <Field label="공통 의견" className="span-2"><textarea className="textarea" value={form.opinion} onChange={e => setForm(v => ({ ...v, opinion: e.target.value }))} /></Field>
      <label className="span-2"><input type="checkbox" checked={form.overwrite} onChange={e => setForm(v => ({ ...v, overwrite: e.target.checked }))} /> 이미 판정한 항목도 덮어쓰기</label>
    </div>
  </Modal>
}

function BulkModal({ reviewID, itemIDs, count, people, onClose, onSaved }: { reviewID: string; itemIDs: string[]; count: number; people: DirectoryUser[]; onClose: () => void; onSaved: () => Promise<void> }) {
  const toast = useToast()
  const [mode, setMode] = useState<'ANSWER' | 'ASSIGN'>('ANSWER')
  const [form, setForm] = useState({ applicability: 'N/A', self_assessment: 'N/A', na_reason: '', current_state: '', action_plan: '', assigned_to: '', overwrite: false })
  const [busy, setBusy] = useState(false)
  const needsReason = mode === 'ANSWER' && form.applicability === 'N/A' && !form.na_reason.trim()
  const submit = async () => {
    setBusy(true)
    try {
      const out = await post<{ applied: number; skipped: number }>(`/api/v1/review-requests/${reviewID}/responses/bulk`, { ...form, item_ids: itemIDs, assign_only: mode === 'ASSIGN' })
      toast.push(mode === 'ASSIGN'
        ? `${out.applied}개 항목의 담당자를 지정했습니다.`
        : out.skipped ? `${out.applied}개 항목에 적용했습니다. 이미 작성된 ${out.skipped}개는 건너뛰었습니다.` : `${out.applied}개 항목에 적용했습니다.`)
      await onSaved()
    } catch (e) { toast.push(errorMessage(e), 'error') } finally { setBusy(false) }
  }
  return <Modal title={`선택한 ${count}개 항목 일괄 처리`} onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant="primary" disabled={busy || needsReason} onClick={submit}>적용</Button></>}>
    <div className="tabs"><button className={`tab ${mode === 'ANSWER' ? 'active' : ''}`} onClick={() => setMode('ANSWER')}>일괄 작성</button><button className={`tab ${mode === 'ASSIGN' ? 'active' : ''}`} onClick={() => setMode('ASSIGN')}>담당자 배정</button></div>
    {mode === 'ASSIGN' ? <>
      <div className="guide-block">긴 체크리스트를 팀에 나눠 맡깁니다. 답변은 건드리지 않고 담당자만 지정하며, 배정된 사람에게 알림이 한 번 발송됩니다.</div>
      <Field label="담당자" required help="심의에 참여하지 않는 사용자에게는 배정할 수 없습니다."><select className="select" value={form.assigned_to} onChange={e => setForm(v => ({ ...v, assigned_to: e.target.value }))}><option value="">지정 해제</option>{people.map(p => <option key={p.id} value={p.id}>{p.display_name}{p.department ? ` · ${p.department}` : ''}</option>)}</select></Field>
    </> : <>
    <div className="guide-block">같은 답변이 반복되는 항목을 한 번에 채웁니다. 결과는 감사로그에 일괄 작업으로 기록되며 개별 항목에서 다시 수정할 수 있습니다.</div>
    <div className="form-grid">
      <Field label="적용 여부" required><select className="select" value={form.applicability} onChange={e => setForm(v => ({ ...v, applicability: e.target.value }))}><option value="Y">Y</option><option value="N">N</option><option value="N/A">N/A</option></select></Field>
      <Field label="자체 판단"><select className="select" value={form.self_assessment} onChange={e => setForm(v => ({ ...v, self_assessment: e.target.value }))}><option value="">선택</option><option value="COMPLIANT">적합</option><option value="INSUFFICIENT">미흡</option><option value="N/A">N/A</option></select></Field>
      {form.applicability === 'N/A' && <Field label="공통 N/A 사유" required className="span-2"><textarea className="textarea" value={form.na_reason} onChange={e => setForm(v => ({ ...v, na_reason: e.target.value }))} /></Field>}
      <Field label="공통 현황" className="span-2"><textarea className="textarea" value={form.current_state} onChange={e => setForm(v => ({ ...v, current_state: e.target.value }))} /></Field>
      <Field label="담당자" help="함께 지정하려면 선택"><select className="select" value={form.assigned_to} onChange={e => setForm(v => ({ ...v, assigned_to: e.target.value }))}><option value="">변경 안 함</option>{people.map(p => <option key={p.id} value={p.id}>{p.display_name}</option>)}</select></Field>
      <div className="span-2"><Toggle label="이미 작성된 항목도 덮어쓰기" value={form.overwrite} onChange={v => setForm(f => ({ ...f, overwrite: v }))} /></div>
    </div></>}
  </Modal>
}

type RuleCandidate = { source_item_id: string; assigned_item_id: string; template_name: string; item_code: string; title: string; category: string }
function RuleOverrideModal({reviewID,onClose,onSaved}:{reviewID:string;onClose:()=>void;onSaved:()=>Promise<void>}) { const toast=useToast(); const [candidates,setCandidates]=useState<RuleCandidate[]>(); const [action,setAction]=useState<'EXCLUDE'|'INCLUDE'>('EXCLUDE'); const [selected,setSelected]=useState(''); const [reason,setReason]=useState(''); useEffect(()=>{get<{items:RuleCandidate[]}>(`/api/v1/review-requests/${reviewID}/rule-candidates`).then(x=>setCandidates(x.items)).catch(e=>toast.push(errorMessage(e),'error'))},[reviewID]); const choices=(candidates||[]).filter(x=>action==='EXCLUDE'?Boolean(x.assigned_item_id):!x.assigned_item_id); useEffect(()=>setSelected(''),[action]); const submit=async()=>{const item=choices.find(x=>x.source_item_id===selected);if(!item)return;try{await post(`/api/v1/review-requests/${reviewID}/rule-overrides`,{action,source_item_id:item.source_item_id,item_id:item.assigned_item_id,reason});toast.push(action==='EXCLUDE'?'자동 배정 항목을 제외했습니다.':'체크리스트 항목을 수동 포함했습니다.');await onSaved();onClose()}catch(e){toast.push(errorMessage(e),'error')}}; return <Modal title="자동 배정 결과 조정" onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant="primary" disabled={!selected||!reason.trim()} onClick={submit}>변경 적용</Button></>}><div className="guide-block">최초 제출 전 자동 Rule 결과만 조정할 수 있으며, 수동 변경 사유와 작업자는 감사로그에 영구 기록됩니다.</div><div className="form-grid" data-sx="sx-036"><Field label="작업"><select className="select" value={action} onChange={e=>setAction(e.target.value as 'EXCLUDE'|'INCLUDE')}><option value="EXCLUDE">자동 배정에서 제외</option><option value="INCLUDE">미배정 항목 수동 포함</option></select></Field><Field label="체크리스트 항목" className="span-2" required><select className="select" value={selected} onChange={e=>setSelected(e.target.value)}><option value="">선택</option>{choices.map(x=><option key={x.source_item_id} value={x.source_item_id}>{x.template_name} · {x.item_code} · {x.title}</option>)}</select></Field><Field label="수동 변경 사유" className="span-2" required><textarea className="textarea" value={reason} onChange={e=>setReason(e.target.value)} /></Field></div></Modal> }

function ItemEditor({ review, item, reviewer, people, onSaved, onSelect }: { review: Review; item: ChecklistItem; reviewer: boolean; people: DirectoryUser[]; onSaved: () => Promise<void>; onSelect: () => void }) {
  const toast = useToast(); const editable = ['DRAFT', 'CHANGE_REQUESTED'].includes(review.status); const reviewable = reviewer && review.status === 'REVIEWING'; const [draft, setDraft] = useState(() => responseFrom(item)); const [saved, setSaved] = useState(''); const [evidence, setEvidence] = useState<File[]>([]); const [uploading, setUploading] = useState(false); const [evidenceDescription, setEvidenceDescription] = useState(''); const [reviewResult, setReviewResult] = useState({ final_applicability: String(item.review_result.final_applicability || ''), result: String(item.review_result.result || ''), opinion: String(item.review_result.opinion || ''), evidence_adequacy: String(item.review_result.evidence_adequacy || ''), na_approved: item.review_result.na_approved as boolean | undefined, follow_up: String(item.review_result.follow_up || ''), follow_up_due_date: String(item.review_result.follow_up_due_date || '') }); const [changeOpen, setChangeOpen] = useState(false); const [pending, setPending] = useState(false); const [conflict, setConflict] = useState<Record<string, unknown>>(); const dirty = useRef(false); const timer = useRef<number | undefined>(undefined)
  // The version this editor loaded. The server rejects a save that would
  // overwrite a newer one, which happens whenever two people hold the same
  // long checklist open.
  const version = useRef(String(item.response.updated_at || ''))
  useEffect(() => { setDraft(responseFrom(item)); dirty.current = false; setPending(false); version.current = String(item.response.updated_at || '') }, [item.response.updated_at])
  const set = (key: keyof ResponseDraft, value: unknown) => { setDraft(v => ({ ...v, [key]: value })); dirty.current = true; setPending(true); if (timer.current) clearTimeout(timer.current); timer.current = window.setTimeout(() => save({ ...draft, [key]: value }), 1200) }
  const save = async (value = draft, force = false) => {
    if (!editable || (!dirty.current && !force)) return
    try {
      const out = await put<{ updated_at: string }>(`/api/v1/review-requests/${review.id}/responses/${item.id}`, { ...value, expected_updated_at: force ? '' : version.current })
      version.current = out.updated_at
      dirty.current = false; setPending(false); setConflict(undefined)
      setSaved(new Date().toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' }))
    } catch (e) {
      if (e instanceof ApiError && e.code === 'RESPONSE_CONFLICT') { setConflict(e.details as Record<string, unknown>); return }
      toast.push(errorMessage(e), 'error')
    }
  }
  // Auto-save is debounced, so closing the tab within that window would drop
  // the last edit without any warning.
  useEffect(() => { if (!pending) return; const warn = (e: BeforeUnloadEvent) => { e.preventDefault(); e.returnValue = '' }; window.addEventListener('beforeunload', warn); return () => window.removeEventListener('beforeunload', warn) }, [pending])
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current) }, [])
  // One requirement is usually evidenced by several screenshots, and each had
  // to be picked, uploaded and waited for on its own. Files are sent one at a
  // time because each becomes its own evidence record, but the person only
  // chooses once, and a failure part-way still keeps what already succeeded.
  const uploadFile = async () => {
    if (!evidence.length) return
    setUploading(true)
    const failed: string[] = []
    let stored = 0
    for (const file of evidence) {
      const form = new FormData()
      form.append('file', file)
      form.append('description', evidenceDescription)
      try {
        await upload(`/api/v1/review-requests/${review.id}/items/${item.id}/evidences`, form)
        stored++
      } catch (e) { failed.push(`${file.name}: ${errorMessage(e)}`) }
    }
    setUploading(false)
    if (stored) toast.push(`증적 ${stored}건을 암호화하여 저장했습니다.`)
    failed.forEach(message => toast.push(message, 'error'))
    if (!failed.length) { setEvidence([]); setEvidenceDescription('') }
    await onSaved()
  }
  const saveReview = async () => { try { await put(`/api/v1/review-requests/${review.id}/review-results/${item.id}`, reviewResult); toast.push('검토 결과를 저장했습니다.'); await onSaved() } catch (e) { toast.push(errorMessage(e), 'error') } }
  return <div className="checklist-editor" onClick={onSelect}><div className="form-grid"><Field label="적용 여부" required><div className="answer-pills">{['Y', 'N', 'N/A'].map(v => <button type="button" disabled={!editable} key={v} className={`answer-pill ${draft.applicability === v ? 'selected' : ''}`} onClick={() => set('applicability', v)}>{v}</button>)}</div></Field><Field label="자체 판단"><select className="select" disabled={!editable} value={draft.self_assessment} onChange={e => set('self_assessment', e.target.value)}><option value="">선택</option><option value="COMPLIANT">적합</option><option value="INSUFFICIENT">미흡</option><option value="N/A">N/A</option></select></Field>{!['YNNA','ASSESSMENT','FILE','GUIDE'].includes(item.answer_type) && <AnswerControl item={item} value={draft.answer} disabled={!editable} onChange={v=>set('answer',v)}/>} {draft.applicability === 'N/A' && <Field className="span-2" label="N/A 사유" required><textarea className="textarea" disabled={!editable} value={draft.na_reason} onChange={e => set('na_reason', e.target.value)} /></Field>}<Field className="span-2" label="현황 및 증적"><textarea className="textarea" disabled={!editable} placeholder="현재 적용 현황과 증적 위치를 구체적으로 작성하세요." value={draft.current_state} onChange={e => set('current_state', e.target.value)} /></Field><Field className="span-2" label="조치 계획"><textarea className="textarea" disabled={!editable} value={draft.action_plan} onChange={e => set('action_plan', e.target.value)} /></Field><Field label="담당자" help="이 항목을 작성할 참여자"><select className="select" disabled={!editable} value={draft.assigned_to} onChange={e => set('assigned_to', e.target.value)}><option value="">지정 안 함</option>{people.map(p => <option key={p.id} value={p.id}>{p.display_name}{p.department ? ` · ${p.department}` : ''}</option>)}</select></Field></div>{editable && <div data-sx="sx-012"><span className="save-state">{pending ? <span className="dirty-dot">저장되지 않은 변경</span> : saved ? <><Check size={13} /> {saved} 자동 저장</> : null}</span><Button small onClick={() => save()}><Save size={13} /> 지금 저장</Button></div>}
    <div data-sx="sx-002"><strong data-sx="sx-018">증적 첨부</strong>{editable && <div className="form-grid" data-sx="sx-028"><Field label="파일" help={evidence.length > 1 ? `${evidence.length}개 선택됨 · 각각 별도 증적으로 저장됩니다` : '여러 개를 한 번에 선택할 수 있습니다'}><input type="file" multiple className="input" onChange={(e: ChangeEvent<HTMLInputElement>) => setEvidence(Array.from(e.target.files || []))} /></Field><Field label="설명"><input className="input" value={evidenceDescription} onChange={e => setEvidenceDescription(e.target.value)} /></Field><div><Button disabled={!evidence.length || uploading} onClick={uploadFile}><Upload size={14} /> {uploading ? '업로드 중…' : evidence.length > 1 ? `${evidence.length}건 암호화 업로드` : '암호화 업로드'}</Button></div></div>}{item.evidences.map(e => <EvidenceRow key={e.id} evidence={e} editable={editable} onSaved={onSaved} />)}</div>
    {!reviewable && <ReviewVerdict result={item.review_result} />}
    {reviewable && <div data-sx="sx-002"><strong data-sx="sx-018">보안 담당자 검토</strong><div className="form-grid" data-sx="sx-028"><Field label="최종 적용 여부"><select className="select" value={reviewResult.final_applicability} onChange={e => setReviewResult(v => ({ ...v, final_applicability: e.target.value }))}><option value="">작성자 판단 유지</option><option value="Y">Y</option><option value="N">N</option><option value="N/A">N/A</option></select></Field><Field label="검토 결과" required><select className="select" value={reviewResult.result} onChange={e => setReviewResult(v => ({ ...v, result: e.target.value }))}><option value="">선택</option><option value="COMPLIANT">적합</option><option value="CONDITIONAL">조건부 적합</option><option value="INSUFFICIENT">미흡</option><option value="NON_COMPLIANT">부적합</option><option value="NA_ACCEPTED">N/A 인정</option><option value="RECHECK">재확인</option></select></Field><Field label="증적 적정성"><select className="select" value={reviewResult.evidence_adequacy} onChange={e => setReviewResult(v => ({ ...v, evidence_adequacy: e.target.value }))}><option value="">선택</option><option value="ADEQUATE">적정</option><option value="PARTIAL">일부 보완</option><option value="INADEQUATE">부적정</option></select></Field><Field label="검토 의견" className="span-2"><textarea className="textarea" value={reviewResult.opinion} onChange={e => setReviewResult(v => ({ ...v, opinion: e.target.value }))} /></Field><Field label="후속조치" className="span-2"><textarea className="textarea" value={reviewResult.follow_up} onChange={e => setReviewResult(v => ({ ...v, follow_up: e.target.value }))} /></Field><Field label="조치 기한" help="심의 리포트의 미조치 항목에서 기한이 지난 건을 구분합니다."><input type="date" className="input" value={reviewResult.follow_up_due_date} onChange={e => setReviewResult(v => ({ ...v, follow_up_due_date: e.target.value }))} /></Field></div><div data-sx="sx-009"><Button variant="danger" onClick={() => setChangeOpen(true)}><MessageSquareWarning size={14} /> 보완 요청</Button><Button variant="primary" onClick={saveReview}><ShieldCheck size={14} /> 검토 저장</Button></div></div>}
    {conflict && <ConflictModal conflict={conflict} onClose={() => setConflict(undefined)} onReload={async () => { setConflict(undefined); dirty.current = false; setPending(false); await onSaved() }} onOverwrite={async () => { await save(draft, true); await onSaved() }} />}
    {changeOpen && <ChangeRequestModal reviewID={review.id} itemID={item.id} onClose={() => setChangeOpen(false)} onSaved={onSaved} />}{item.change_requests.filter(c => c.status === 'OPEN' && editable).map(c => <ChangeAnswer key={c.id} change={c} onSaved={onSaved} />)}</div>
}

function EvidenceRow({evidence,editable,onSaved}:{evidence:ChecklistItem['evidences'][number];editable:boolean;onSaved:()=>Promise<void>}) { const toast=useToast(); const save=useDownload(); const [file,setFile]=useState<File>(); const replace=async()=>{if(!file)return;const form=new FormData();form.append('file',file);try{await upload(`/api/v1/evidences/${evidence.id}/versions`,form);toast.push(`증적 v${evidence.current_version+1}을 등록했습니다.`);setFile(undefined);await onSaved()}catch(e){toast.push(errorMessage(e),'error')}};const remove=async()=>{if(!confirm(`${evidence.original_filename} 증적을 삭제할까요?`))return;try{await del(`/api/v1/evidences/${evidence.id}`);toast.push('증적을 논리 삭제했습니다.');await onSaved()}catch(e){toast.push(errorMessage(e),'error')}};return <div className="evidence-item"><FileCheck2 size={14}/><div data-sx="sx-017"><button type="button" className="table-link" onClick={() => save(`/api/v1/evidences/${evidence.id}/download`)}>{evidence.original_filename}</button><div className="subtle">{formatBytes(evidence.size_bytes)} · v{evidence.current_version} <ScanBadge status={evidence.scan_status} detail={String(evidence.scan_detail || '')} /></div></div><EvidencePreview evidence={evidence} />{editable&&<><input type="file" className="input" data-sx="sx-041" onChange={e=>setFile(e.target.files?.[0])}/><Button small disabled={!file} onClick={replace}><RefreshCw size={12}/> 새 버전</Button><Button small variant="danger" aria-label={`${evidence.original_filename} 증적 삭제`} onClick={remove}><Trash2 size={12}/></Button></>}</div>}

function ChangeRequestModal({ reviewID, itemID, onClose, onSaved }: { reviewID: string; itemID: string; onClose: () => void; onSaved: () => Promise<void> }) { const toast = useToast(); const [reason, setReason] = useState(''); const [due, setDue] = useState(''); const submit = async () => { try { await post(`/api/v1/review-requests/${reviewID}/change-requests`, { item_id: itemID, reason, due_date: due, assignee_id: '' }); toast.push('보완 요청을 등록했습니다.'); onClose(); await onSaved() } catch (e) { toast.push(errorMessage(e), 'error') } }; return <Modal title="항목 보완 요청" onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant="danger" disabled={!reason} onClick={submit}>보완 요청</Button></>}><div className="form-grid"><Field label="보완 사유" required className="span-2"><textarea className="textarea" value={reason} onChange={e => setReason(e.target.value)} /></Field><Field label="완료 예정일"><input type="date" className="input" value={due} onChange={e => setDue(e.target.value)} /></Field></div></Modal> }
function ChangeAnswer({ change, onSaved }: { change: ChangeRequest; onSaved: () => Promise<void> }) { const toast = useToast(); const [answer, setAnswer] = useState(change.answer || ''); const submit = async () => { try { await api(`/api/v1/change-requests/${change.id}`, { method: 'PATCH', body: JSON.stringify({ answer, status: 'DONE' }) }); toast.push('보완 조치를 완료했습니다.'); await onSaved() } catch (e) { toast.push(errorMessage(e), 'error') } }; return <div className="change-item"><Badge tone="amber">보완 요청</Badge><p>{change.reason}</p><textarea className="textarea" placeholder="조치 내용" value={answer} onChange={e => setAnswer(e.target.value)} /><Button small variant="primary" onClick={submit}>조치 완료</Button></div> }
function CommentBox({reviewID,item,onSaved}:{reviewID:string;item:ChecklistItem;onSaved:()=>Promise<void>}){const toast=useToast();const[body,setBody]=useState('');const submit=async()=>{try{await post(`/api/v1/review-requests/${reviewID}/items/${item.id}/comments`,{body});setBody('');await onSaved()}catch(e){toast.push(errorMessage(e),'error')}};return <><h4>항목 코멘트 ({item.comments?.length||0})</h4>{item.comments?.map(c=><div className="change-item" key={c.id}><strong>{c.author_name}</strong><div className="subtle">{formatDate(c.created_at,true)}</div><p>{c.body}</p></div>)}<textarea className="textarea" placeholder="작성자와 검토자가 함께 보는 코멘트" value={body} onChange={e=>setBody(e.target.value)}/><Button small disabled={!body.trim()} onClick={submit}><MessageSquareWarning size={13}/> 코멘트 등록</Button></>}
function AnswerControl({item,value,disabled,onChange}:{item:ChecklistItem;value:unknown;disabled:boolean;onChange:(v:unknown)=>void}){const options=(item.options||[]).map(x=>typeof x==='string'?x:String((x as Record<string,unknown>).label||(x as Record<string,unknown>).value||''));const scalar=typeof value==='object'&&value!==null?'value'in value?String((value as Record<string,unknown>).value??''):'' : String(value??'');if(item.answer_type==='MULTI_SELECT'){const selected=Array.isArray((value as Record<string,unknown>)?.values)?(value as Record<string,unknown>).values as string[]:[];return <Field className="span-2" label="다중 선택"><div className="answer-pills">{options.map(x=><label className={`answer-pill ${selected.includes(x)?'selected':''}`} key={x}><input type="checkbox" disabled={disabled} checked={selected.includes(x)} onChange={e=>onChange({values:e.target.checked?[...selected,x]:selected.filter(v=>v!==x)})}/> {x}</label>)}</div></Field>};if(item.answer_type==='REPEAT_TABLE'){const rows=Array.isArray((value as Record<string,unknown>)?.rows)?(value as Record<string,unknown>).rows as string[]:[];return <Field className="span-2" label="반복 목록"><div>{rows.map((row,i)=><div data-sx="sx-015" key={i}><input className="input" disabled={disabled} value={row} onChange={e=>onChange({rows:rows.map((v,n)=>n===i?e.target.value:v)})}/><Button small variant="danger" disabled={disabled} onClick={()=>onChange({rows:rows.filter((_,n)=>n!==i)})}>삭제</Button></div>)}<Button small disabled={disabled} onClick={()=>onChange({rows:[...rows,'']})}>행 추가</Button></div></Field>};if(item.answer_type==='SINGLE_SELECT')return <Field className="span-2" label="선택 답변"><select className="select" disabled={disabled} value={scalar} onChange={e=>onChange({value:e.target.value})}><option value="">선택</option>{options.map(x=><option key={x}>{x}</option>)}</select></Field>;if(item.answer_type==='USER')return <UserAnswer value={scalar} disabled={disabled} onChange={v=>onChange({value:v})}/>;if(item.answer_type==='LONG_TEXT')return <Field className="span-2" label="상세 답변"><textarea className="textarea" disabled={disabled} value={scalar} onChange={e=>onChange({value:e.target.value})}/></Field>;const type=item.answer_type==='NUMBER'?'number':item.answer_type==='DATE'?'date':item.answer_type==='URL'?'url':'text';return <Field className="span-2" label="항목 답변"><input className="input" type={type} disabled={disabled} value={scalar} onChange={e=>onChange({value:type==='number'?(e.target.value===''?'':Number(e.target.value)):e.target.value})}/></Field>}
function UserAnswer({value,disabled,onChange}:{value:string;disabled:boolean;onChange:(v:string)=>void}){const[users,setUsers]=useState<DirectoryUser[]>([]);useEffect(()=>{get<DirectoryUser[]>('/api/v1/users/directory').then(setUsers)},[]);return <Field className="span-2" label="담당자"><select className="select" disabled={disabled} value={value} onChange={e=>onChange(e.target.value)}><option value="">선택</option>{users.map(u=><option key={u.id} value={u.id}>{u.display_name} · {u.department||u.username}</option>)}</select></Field>}
function DecisionModal({ kind, busy, onClose, onSubmit }: { kind: 'complete' | 'approval' | 'reject'; busy: boolean; onClose: () => void; onSubmit: (data: unknown) => void }) { const [comment, setComment] = useState(''); const [result, setResult] = useState('APPROVED'); const complete = kind === 'complete'; return <Modal title={complete ? '검토 완료' : kind === 'approval' ? '최종 승인' : '심의 반려'} onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant={kind === 'reject' ? 'danger' : 'primary'} disabled={busy} onClick={() => onSubmit(complete ? { final_opinion: comment, final_result: result } : { comment })}>{complete ? '검토 완료' : kind === 'approval' ? '승인' : '반려'}</Button></>}><div className="form-grid">{complete && <Field label="심의 결과"><select className="select" value={result} onChange={e => setResult(e.target.value)}><option value="APPROVED">승인</option><option value="CONDITIONAL">조건부 승인</option><option value="REJECTED">반려</option></select></Field>}<Field label={complete ? '최종 의견' : '의견'} className="span-2"><textarea className="textarea" value={comment} onChange={e => setComment(e.target.value)} /></Field></div></Modal> }

// The verdict used to be visible only inside the panel the reviewer edits it
// in, which needs the review to be under review and the reader to be the
// reviewer. So the person whose service it is never saw why an item was
// judged as it was, nor the action they were being asked to take -- and a
// reminder about that action linked them to a page that did not show it.
function ReviewVerdict({ result }: { result: Record<string, unknown> }) {
  const verdict = String(result?.result || '')
  const opinion = String(result?.opinion || '')
  const action = String(result?.follow_up || '')
  if (!verdict && !opinion && !action) return null
  const due = String(result?.follow_up_due_date || '').slice(0, 10)
  const doneOn = String(result?.follow_up_done_at || '').slice(0, 10)
  const late = Boolean(due) && !doneOn && due < new Date().toISOString().slice(0, 10)
  return <div data-sx="sx-002">
    <strong data-sx="sx-018">보안 담당자 검토 결과</strong>
    <div className="form-grid">
      {verdict && <Field label="검토 결과"><div><Badge tone={verdictTone[verdict] || ''}>{verdictLabel[verdict] || verdict}</Badge></div></Field>}
      {result?.final_applicability ? <Field label="최종 적용 여부"><div>{String(result.final_applicability)}</div></Field> : null}
      {opinion && <Field label="검토 의견" className="span-2"><p className="subtle">{opinion}</p></Field>}
      {action && <Field label="후속조치" className="span-2">
        <p>{action}</p>
        {doneOn ? <span className="badge green">{doneOn} 이행 완료</span>
          : due ? <span className={`badge ${late ? 'red' : 'amber'}`}>{late ? `${due} 기한 초과` : `${due}까지`}</span>
            : <span className="subtle">기한 없음</span>}
        {result?.follow_up_note ? <p className="subtle">{String(result.follow_up_note)}</p> : null}
      </Field>}
    </div>
  </div>
}

const verdictLabel: Record<string, string> = { COMPLIANT: '적합', CONDITIONAL: '조건부 적합', INSUFFICIENT: '미흡', NON_COMPLIANT: '부적합', NA_ACCEPTED: 'N/A 인정', RECHECK: '재확인' }
const verdictTone: Record<string, 'green' | 'amber' | 'red' | ''> = { COMPLIANT: 'green', CONDITIONAL: 'amber', INSUFFICIENT: 'amber', NON_COMPLIANT: 'red', RECHECK: 'amber' }
