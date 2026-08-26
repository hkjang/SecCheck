import { ChangeEvent, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { AlertTriangle, ArrowLeft, HelpCircle, RotateCcw, Check, CheckCircle2, CheckSquare, ChevronDown, ChevronRight, ChevronUp, Copy, Download, FileCheck2, FilePlus2, Filter, ListChecks, MessageSquareWarning, Paperclip, Play, RefreshCw, History, Save, Search, Send, ShieldCheck, SlidersHorizontal, Trash2, UserRound, Upload, ZoomIn } from 'lucide-react'
import { api, del, directory, errorMessage, get, post, put, upload, ApiError } from '../lib/api'
import { ChangeRequest, ChecklistItem, DirectoryUser, Review } from '../lib/types'
import { Badge, Button, Empty, Field, LongText, PeopleField, formatBytes, formatDate, LoadFailed, Loading, Modal, StatusBadge, Toggle, useDownload, useToast } from '../components/ui'
import { useAuth } from '../main'

type ResponseDraft = { answer: unknown; applicability: string; self_assessment: string; current_state: string; na_reason: string; action_plan: string; assigned_to: string }
const responseFrom = (item: ChecklistItem): ResponseDraft => ({ answer: item.response.answer_json || {}, applicability: String(item.response.applicability || ''), self_assessment: String(item.response.self_assessment || ''), current_state: String(item.response.current_state || ''), na_reason: String(item.response.na_reason || ''), action_plan: String(item.response.action_plan || ''), assigned_to: String(item.response.assigned_to || '') })

// A change request hands the review back to the author, who may edit any item
// while it is there -- not only the one that was asked about. A verdict older
// than the answer or the evidence it judged is stale; the server decides that,
// so the badge, the filter and the completion guard cannot drift apart.
// A deadline already in the past is refused by the server, so the picker does
// not offer one.
const todayISO = () => new Date().toISOString().slice(0, 10)

// The rules behind these are the service's, and it now says so per item: the
// screen used to work them out again from the raw rows, which is how "증적
// 누락" came to count N/A items the submission guard exempts.
const flagsOf = (item: ChecklistItem) => item.flags || { missing_answer: !item.response.applicability, missing_evidence: item.evidence_required && !item.evidences.length, open_change: item.change_requests.some(c => c.status !== 'VERIFIED'), stale_verdict: item.stale_verdict === true, carried: Boolean(item.response?.carried_at), commented: item.comments.length > 0, result: String(item.review_result?.result || '') }
const answerChangedSinceReview = (item: ChecklistItem) => flagsOf(item).stale_verdict

// A re-review copies last year's answers in, which is the point of it -- but a
// copied answer looked exactly like one somebody wrote this cycle. Any save
// clears the mark, so what stays marked is what nobody looked at again.
const carriedOver = (item: ChecklistItem) => flagsOf(item).carried

// The filter names double as deep-link targets: the dashboard sends people
// straight to '내 담당 항목' in the review that has their work.
const itemFilters = ['ALL', 'MISSING', 'NA', 'EVIDENCE', 'CHANGE', 'MINE', 'STALE', 'CARRIED', 'COMMENT', 'FINDING', 'BLOCKED']

export default function ReviewDetail() {
  const save = useDownload()
  const { id = '' } = useParams(); const { user } = useAuth(); const toast = useToast(); const navigate = useNavigate()
  // A notice about one item can now say which one, so arriving from the
  // notification centre opens that item instead of a list of a few hundred.
  const [search] = useSearchParams(); const focusRequest = search.get('item') || ''; const filterRequest = search.get('filter') || ''
  const [review, setReview] = useState<Review>(); const [items, setItems] = useState<ChecklistItem[]>(); const [selected, setSelected] = useState<string>(''); const [open, setOpen] = useState<Set<string>>(new Set()); const [query, setQuery] = useState(''); const [filter, setFilter] = useState(itemFilters.includes(filterRequest) ? filterRequest : 'ALL'); const [validation, setValidation] = useState<Record<string, unknown>[] | null>(null); const [dialog, setDialog] = useState<'complete' | 'approval' | 'reject' | 'reopen' | 'withdraw' | null>(null); const [ruleOpen, setRuleOpen] = useState(false); const [busy, setBusy] = useState(false); const [picked, setPicked] = useState<Set<string>>(new Set()); const [bulkOpen, setBulkOpen] = useState(false); const [historyOpen, setHistoryOpen] = useState(false); const [precheck, setPrecheck] = useState<{ ready: boolean; issues: Record<string, unknown>[] }>(); const [handover, setHandover] = useState(false)
  const reviewer = user.roles.includes('SECURITY_REVIEWER')
  // The submission rules live on the server and used to be reported only by
  // the 422 that came back from pressing 제출 -- which only the requester could
  // press. Asking for the same report up front means everyone working on the
  // review can see what is still blocking it.
  const load = async () => { const [r, i] = await Promise.all([get<Review>(`/api/v1/review-requests/${id}`), get<ChecklistItem[]>(`/api/v1/review-requests/${id}/items`)]); setReview(r); setItems(i); if (!selected && i[0]) setSelected(i[0].id); const gate = ['DRAFT', 'CHANGE_REQUESTED'].includes(r.status) ? 'submission-check' : r.status === 'REVIEWING' && reviewer ? 'completion-check' : ''; if (gate) { try { setPrecheck(await get<{ ready: boolean; issues: Record<string, unknown>[] }>(`/api/v1/review-requests/${id}/${gate}`)) } catch { setPrecheck(undefined) } } else setPrecheck(undefined) }
  const [failed, setFailed] = useState<unknown>()
  useEffect(() => { setFailed(undefined); load().catch(setFailed) }, [id])
  const blocked = useMemo(() => new Set((precheck?.issues || []).map(x => String(x.item_id || ''))), [precheck])
  const filtered = useMemo(() => (items || []).filter(item => { const hit = !query || `${item.item_code} ${item.title} ${item.question}`.toLowerCase().includes(query.toLowerCase()); if (!hit) return false; if (filter === 'MISSING') return flagsOf(item).missing_answer; if (filter === 'NA') return item.response.applicability === 'N/A'; if (filter === 'EVIDENCE') return flagsOf(item).missing_evidence; if (filter === 'CHANGE') return flagsOf(item).open_change; if (filter === 'COMMENT') return flagsOf(item).commented; if (filter === 'FINDING') return ['INSUFFICIENT', 'NON_COMPLIANT', 'CONDITIONAL', 'RECHECK'].includes(flagsOf(item).result); if (filter === 'MINE') return item.response.assigned_to === user.id; if (filter === 'STALE') return answerChangedSinceReview(item); if (filter === 'CARRIED') return carriedOver(item); if (filter === 'BLOCKED') return blocked.has(item.id); return true }), [items, query, filter, user.id, blocked])
  const sections = useMemo(() => Array.from(new Set((items || []).map(x => `${x.template_name} · ${x.section || '일반'}`))), [items])
  // Showing how much is left per filter turns the dropdown into a to-do list
  // instead of a blind switch.
  const counts = useMemo(() => { const all = items || []; return { ALL: all.length, MISSING: all.filter(x => flagsOf(x).missing_answer).length, NA: all.filter(x => x.response.applicability === 'N/A').length, EVIDENCE: all.filter(x => flagsOf(x).missing_evidence).length, CHANGE: all.filter(x => flagsOf(x).open_change).length, COMMENT: all.filter(x => flagsOf(x).commented).length, FINDING: all.filter(x => ['INSUFFICIENT', 'NON_COMPLIANT', 'CONDITIONAL', 'RECHECK'].includes(flagsOf(x).result)).length, MINE: all.filter(x => x.response.assigned_to === user.id).length, STALE: all.filter(answerChangedSinceReview).length, CARRIED: all.filter(carriedOver).length, BLOCKED: all.filter(x => blocked.has(x.id)).length } }, [items, user.id, blocked])
  const [people, setPeople] = useState<DirectoryUser[]>([])
  useEffect(() => { directory<DirectoryUser>().then(setPeople).catch(() => undefined) }, [])
  // Only the people who can open this review may hold an item in it, and the
  // save enforces exactly that. Offering the whole directory instead put a
  // refusal -- or an item nobody could reach -- one click away.
  const [assignees, setAssignees] = useState<DirectoryUser[]>([])
  useEffect(() => { get<{ items: DirectoryUser[] }>(`/api/v1/review-requests/${id}/assignees`).then(out => setAssignees(out.items)).catch(() => undefined) }, [id])
  const nameOf = (v: unknown) => { const key = String(v || ''); return assignees.find(p => p.id === key)?.display_name || people.find(p => p.id === key)?.display_name || '' }
  // Jumping straight to a flagged item is the point of the submission report;
  // the active filter is cleared first so the target is never hidden.
  const focusItem = (code: string) => { const target = (items || []).find(x => x.item_code === code); if (!target) return; setValidation(null); setFilter('ALL'); setQuery(''); setSelected(target.id); setOpen(v => new Set(v).add(target.id)); window.setTimeout(() => document.getElementById(`item-${target.id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 60) }
  useEffect(() => {
    if (!focusRequest || !items?.some(x => x.id === focusRequest)) return
    setFilter('ALL'); setQuery(''); setSelected(focusRequest)
    setOpen(v => new Set(v).add(focusRequest))
    const timer = window.setTimeout(() => document.getElementById(`item-${focusRequest}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 80)
    return () => clearTimeout(timer)
  }, [focusRequest, items])
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
  const action = async (path: string, data?: unknown) => { setBusy(true); try { const out = await post<{ status: string }>(`/api/v1/review-requests/${id}/${path}`, data); toast.push(`상태가 ${out.status}(으)로 변경되었습니다.`); setDialog(null); await load() } catch (e) { if (e instanceof ApiError && e.code === 'SUBMISSION_INCOMPLETE') setValidation(e.details as Record<string, unknown>[]); else if (e instanceof ApiError && e.code === 'REVIEW_INCOMPLETE' && Array.isArray((e.details as { issues?: Record<string, unknown>[] })?.issues)) setValidation((e.details as { issues: Record<string, unknown>[] }).issues); else toast.push(errorMessage(e), 'error') } finally { setBusy(false) } }
  const verifyChange=async(changeID:string)=>{try{await api(`/api/v1/change-requests/${changeID}`,{method:'PATCH',body:JSON.stringify({status:'VERIFIED',answer:''})});toast.push('보완 조치를 검증 완료했습니다.');await load()}catch(e){toast.push(errorMessage(e),'error')}}
  if (failed) return <LoadFailed error={failed} onRetry={() => { setFailed(undefined); load().catch(setFailed) }} />
  if (!review || !items) return <Loading />
  // The three counts the completion guard refuses on. Showing them next to the
  // button means a reviewer knows what is left before pressing it, instead of
  // being told afterwards.
  const blockers = review.completion_blockers
  const blockersLeft = blockers ? ([['미검토', blockers.unreviewed_items], ['미검증 보완', blockers.unverified_changes], ['판정 후 변경', blockers.stale_verdicts]] as const).filter(([, n]) => n > 0).map(([label, n]) => `${label} ${n}건`) : []
  // The service decides both of these, with the same helpers its write
  // handlers refuse on; the status alone was never the whole rule.
  const editable = review.can_edit === true
  const judging = review.can_review === true && review.status === 'REVIEWING'
  const selecting = editable || judging
  const progress = review.progress || { total: items.length, answered: items.filter(x => x.response.applicability).length, evidence: 0 }; const percent = progress.total ? Math.round(progress.answered / progress.total * 100) : 0; const results=(review.result_summary||{}) as Record<string,number>
  // The requester is who may cancel the review and who every default notice
  // goes to, so it has to be possible to hand that over when somebody moves on.
  const canHandOver = review.requester_id === user.id || user.roles.includes('SYSTEM_ADMIN')
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
  return <div className="page" data-sx="sx-038"><div className="page-header"><div><Button variant="ghost" small onClick={() => navigate(-1)}><ArrowLeft size={14} /> 목록</Button><h1 className="page-title" data-sx="sx-035">{review.service_name}</h1><p className="page-description">{review.review_number} · {review.department} · {review.service_type}</p></div><div className="header-actions"><StatusBadge status={review.status} /><Button onClick={() => setHistoryOpen(true)}><History size={14} /> 이력</Button>{user.roles.includes('REQUESTER') && <Button onClick={copyReview}><Copy size={14}/> 재심의 복사</Button>}{review.status === 'DRAFT' && user.roles.includes('TEMPLATE_ADMIN') && <Button onClick={() => setRuleOpen(true)}><SlidersHorizontal size={14}/> 자동 배정 조정</Button>}{canHandOver&&review.status!=='CANCELLED'&&<Button onClick={()=>setHandover(true)}><UserRound size={14}/> 요청자 인계</Button>}{review.requester_id===user.id&&['DRAFT','CHANGE_REQUESTED','SUBMITTED','RESUBMITTED','REVIEWING','APPROVAL_PENDING'].includes(review.status)&&<Button variant="danger" onClick={()=>{if(review.status==='DRAFT'){if(confirm('이 심의를 취소할까요?'))action('cancel');return}const reason=prompt('검토가 시작된 심의입니다. 취소 사유를 적어 주세요. 검토자·승인자에게 그대로 전달됩니다.');if(reason&&reason.trim())action('cancel',{reason})}}>요청 취소</Button>}{precheck && (precheck.ready ? <Badge tone="green">{review.status === 'REVIEWING' ? '검토 완료 가능' : '제출 준비 완료'}</Badge> : <Button onClick={() => setValidation(precheck.issues)}><AlertTriangle size={14} /> {review.status === 'REVIEWING' ? '검토 완료 전 점검' : '제출 전 점검'} {precheck.issues.length}건</Button>)}{editable && <Button variant="primary" disabled={busy} onClick={() => action('submit')}><Send size={14} /> {review.status === 'DRAFT' ? '제출' : '재제출'}</Button>}{reviewer && ['SUBMITTED', 'RESUBMITTED'].includes(review.status) && <Button variant="primary" disabled={busy} onClick={() => action('begin-review')}><Play size={14} /> 검토 시작</Button>}{reviewer && review.status === 'REVIEWING' && review.reviewer_can_act === false && <><Badge tone="red">담당 검토자 권한 없음</Badge><Button variant="primary" disabled={busy} onClick={() => action('begin-review')}><Play size={14} /> 검토 이어받기</Button></>}{judging && <>{blockersLeft.length > 0 && <Badge tone="amber">{blockersLeft.join(' · ')} 남음</Badge>}<Button onClick={() => setDialog('complete')}><CheckCircle2 size={14} /> 검토 완료</Button></>}{reviewer&&review.status==='REJECTED'&&<Button onClick={()=>setDialog('reopen')}><RotateCcw size={14} /> 보완 재개</Button>}{reviewer&&review.status==='APPROVAL_PENDING'&&review.reviewer_id===user.id&&<Button onClick={()=>setDialog('withdraw')}><RotateCcw size={14} /> 결재 요청 회수</Button>}{reviewer&&review.reviewer_id===user.id&&['APPROVED','REJECTED'].includes(review.status)&&<Button onClick={()=>action('close')}>심의 종료</Button>}{review.can_approve === true && <><Button variant="danger" onClick={() => setDialog('reject')}>반려</Button><Button variant="success" onClick={() => setDialog('approval')}><ShieldCheck size={14} /> 최종 승인</Button></>}</div></div>
    <div className="card" data-sx="sx-027"><div className="card-body review-summary-grid"><div><span className="subtle">작성 진행률</span><div data-sx="sx-020">{percent}% <span className="subtle">({progress.answered}/{progress.total})</span></div></div><div><div className="progress"><progress value={percent} max={100}>{percent}%</progress></div></div><div><span className="subtle">진행 경과</span><div className="subtle"><ReviewDates review={review} /></div></div><div><span className="subtle">검토 집계</span><div data-sx="sx-037"><Badge tone="green">적합 {results.compliant||0}</Badge><Badge tone="amber">조건부 {results.conditional||0}</Badge>{counts.FINDING > 0 ? <button type="button" className="link-button" title="지적 항목만 보기" onClick={() => setFilter('FINDING')}><Badge tone="red">미흡·부적합·조건부 {counts.FINDING}</Badge></button> : <Badge tone="red">미흡·부적합 {(results.insufficient||0)+(results.non_compliant||0)}</Badge>}<Badge>N/A {results.na||0}</Badge></div></div><div className="header-actions"><TemplateVersions review={review} /><Button small onClick={() => save(`/api/v1/review-requests/${id}/export/xlsx`)}><Download size={13} /> Excel</Button><Button small onClick={() => save(`/api/v1/review-requests/${id}/export/pdf`)}><Download size={13} /> PDF</Button><Button small onClick={() => save(`/api/v1/review-requests/${id}/export/zip`)}><Download size={13} /> ZIP</Button></div></div></div>
    <div className="toolbar"><div className="search-box"><Search /><input className="input" placeholder="항목코드, 보안요건, 질문 검색" value={query} onChange={e => setQuery(e.target.value)} /></div><Filter size={16} color="#6d7a8e" /><select className="select" data-sx="sx-051" value={filter} onChange={e => setFilter(e.target.value)}><option value="ALL">전체 항목 ({counts.ALL})</option><option value="MISSING">미작성 ({counts.MISSING})</option><option value="NA">N/A ({counts.NA})</option><option value="EVIDENCE">증적 누락 ({counts.EVIDENCE})</option><option value="CHANGE">보완 요청 ({counts.CHANGE})</option><option value="MINE">내 담당 항목 ({counts.MINE})</option><option value="STALE">답변 변경됨 ({counts.STALE})</option><option value="CARRIED">이월 답변 ({counts.CARRIED})</option>{counts.COMMENT > 0 && <option value="COMMENT">코멘트 있음 ({counts.COMMENT})</option>}{counts.FINDING > 0 && <option value="FINDING">지적 항목 ({counts.FINDING})</option>}{counts.BLOCKED > 0 && <option value="BLOCKED">{review.status === 'REVIEWING' ? '완료 불가' : '제출 불가'} ({counts.BLOCKED})</option>}</select></div>
    <ReviewOutcome review={review} />
    <ReviewParticipants reviewID={review.id} editable={editable} onSaved={load} />

    <div className="review-layout"><aside className="card section-nav"><div className="card-header"><h3>섹션 이동</h3><Badge>{items.length}</Badge></div><div className="card-body" data-sx="sx-044">{sections.map(section => <button key={section} onClick={() => document.getElementById(`section-${sections.indexOf(section)}`)?.scrollIntoView({ behavior: 'smooth' })}><span>{section}</span><ChevronRight size={13} /></button>)}</div></aside>
      <section className="checklist-list">{filtered.length ? filtered.map((item, index) => { const sectionName = `${item.template_name} · ${item.section || '일반'}`; const sectionIndex = sections.indexOf(sectionName); const previous = index > 0 ? `${filtered[index - 1].template_name} · ${filtered[index - 1].section || '일반'}` : ''; const expanded = open.has(item.id); return <div key={item.id}>{sectionName !== previous && <div id={`section-${sectionIndex}`} data-sx="sx-025">{sectionName} <Badge tone="blue">{item.template_version}</Badge></div>}<article className="checklist-card" id={`item-${item.id}`}><div className="checklist-summary" onClick={() => { setSelected(item.id); setOpen(v => { const n = new Set(v); n.has(item.id) ? n.delete(item.id) : n.add(item.id); return n }) }}><div>{selecting && <input type="checkbox" className="item-select" aria-label={`${item.item_code} 선택`} checked={picked.has(item.id)} onClick={e => e.stopPropagation()} onChange={() => togglePick(item.id)} />}<span className="item-code">{item.item_code}</span> <span className={`badge severity-${item.severity}`}>{item.severity}</span>{item.evidence_required && <Badge tone="amber">증적 필수</Badge>}{answerChangedSinceReview(item) && <Badge tone="red"><RefreshCw size={11} /> 검토 후 답변 변경</Badge>}{carriedOver(item) && <Badge tone="purple">이월 답변</Badge>}{item.response.assigned_to ? <Badge tone={item.response.assigned_to === user.id ? 'blue' : 'purple'}><UserRound size={11} /> {nameOf(item.response.assigned_to) || '담당자'}</Badge> : null}<div className="item-title">{item.title}</div><div className="item-question">{item.question}</div></div><div>{item.response.applicability ? <Badge tone={item.response.applicability === 'N/A' ? 'amber' : 'green'}>{String(item.response.applicability)}</Badge> : <Badge>미작성</Badge>} <button type="button" className="row-toggle" aria-expanded={expanded} aria-label={`${item.item_code} ${expanded ? '접기' : '펼치기'}`} onClick={e => { e.stopPropagation(); setSelected(item.id); setOpen(v => { const n = new Set(v); n.has(item.id) ? n.delete(item.id) : n.add(item.id); return n }) }}>{expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</button></div></div>{expanded && <ItemEditor review={review} item={item} reviewer={reviewer} people={assignees} onSaved={load} onSelect={() => setSelected(item.id)} />}</article></div> }) : <Empty title="필터 조건에 맞는 항목이 없습니다." />}</section>
      <aside className="card detail-panel"><div className="card-header"><h3>항목 상세</h3>{current && <Badge tone="blue">{current.item_code}</Badge>}{filtered.length > 0 && <div className="header-actions"><span className="subtle">{position >= 0 ? position + 1 : '-'} / {filtered.length}</span><Button small aria-label="이전 항목 (Alt+위쪽 화살표)" title="이전 항목 (Alt+↑)" disabled={position <= 0} onClick={() => step(-1)}><ChevronUp size={13} /></Button><Button small aria-label="다음 항목 (Alt+아래쪽 화살표)" title="다음 항목 (Alt+↓)" disabled={position < 0 || position >= filtered.length - 1} onClick={() => step(1)}><ChevronDown size={13} /></Button></div>}</div><div className="card-body">{current ? <><strong>{current.title}</strong><p className="subtle" data-sx="sx-022">{current.question}</p><h4>점검 가이드</h4><div className="guide-block">{current.guide || '등록된 가이드가 없습니다.'}</div>{current.legal_basis && <><h4>관련 근거</h4><p className="subtle" data-sx="sx-049">{current.legal_basis}</p></>}{current.example && <><h4>작성 예시</h4><div className="guide-block">{current.example}</div></>}<h4>증적 ({current.evidences.length})</h4>{current.evidences.map(e => <div className="evidence-item" key={e.id}><button type="button" className="table-link" onClick={() => save(`/api/v1/evidences/${e.id}/download`)}><Paperclip size={13} /> {e.original_filename}</button><div className="subtle">{formatBytes(e.size_bytes)} · v{e.current_version} <ScanBadge status={e.scan_status} detail={String(e.scan_detail || '')} /></div><EvidencePreview evidence={e} /></div>)}<h4>보완 요청</h4>{current.change_requests.length ? current.change_requests.map(c => <div className="change-item" key={c.id}><StatusBadge status={c.status} /><p>{c.reason}</p>{c.answer&&<div className="guide-block">{c.answer}</div>}{c.due_date && <div className="subtle">기한 {formatDate(c.due_date)}</div>}{judging&&c.status==='DONE'&&<Button small variant="primary" onClick={()=>verifyChange(c.id)}><Check size={13}/> 조치 검증</Button>}</div>) : <p className="subtle">보완 요청이 없습니다.</p>}<CommentBox reviewID={review.id} item={current} onSaved={load} /></> : <Empty title="항목을 선택하세요." />}</div></aside></div>
    {selecting && picked.size > 0 && <div className="bulk-bar" role="region" aria-label="선택한 항목 일괄 작업"><CheckSquare size={16} /><strong>{picked.size}개 항목 선택됨</strong><Button small onClick={() => setPicked(new Set(filtered.map(x => x.id)))}>보이는 항목 모두</Button><Button small onClick={() => setPicked(new Set())}>선택 해제</Button><Button small variant="primary" onClick={() => setBulkOpen(true)}><ListChecks size={13} /> {judging ? '일괄 판정' : '일괄 처리'}</Button></div>}
    {handover && <HandoverModal reviewID={id} onClose={() => setHandover(false)} onSaved={async () => { setHandover(false); await load() }} />}
    {historyOpen && <HistoryModal reviewID={id} onClose={() => setHistoryOpen(false)} />}
    {bulkOpen && judging && <BulkReviewModal reviewID={id} itemIDs={Array.from(picked)} count={picked.size} people={assignees} onClose={() => setBulkOpen(false)} onSaved={async () => { setBulkOpen(false); setPicked(new Set()); await load() }} />}
    {bulkOpen && !judging && <BulkModal reviewID={id} itemIDs={Array.from(picked)} count={picked.size} people={assignees} onClose={() => setBulkOpen(false)} onSaved={async () => { setBulkOpen(false); setPicked(new Set()); await load() }} />}
    {validation && <Modal title={review.status === 'REVIEWING' ? '검토 완료 전 확인이 필요합니다' : '제출 전 확인이 필요합니다'} onClose={() => setValidation(null)} footer={<Button variant="primary" onClick={() => setValidation(null)}>확인</Button>}><p className="subtle">서버 검증에서 {validation.length}개 항목이 남아 있습니다. 항목을 누르면 해당 위치로 이동합니다.</p>{validation.map((issue, i) => <div className="change-item" key={i}><button className="link-button" onClick={() => focusItem(String(issue.item_code))}><strong>{String(issue.item_code)} {String(issue.title)}</strong></button><ul>{(issue.reasons as string[]).map(x => <li key={x}>{x}</li>)}</ul></div>)}</Modal>}
    {review.status === 'APPROVAL_PENDING' && <ApprovalBrief reviewID={review.id} />}
    {dialog && <DecisionModal kind={dialog} busy={busy} draft={dialog === 'complete' ? completionDraft(items || [], results) : ''} suggested={dialog === 'complete' ? suggestedResult(results) : ''} onClose={() => setDialog(null)} onSubmit={(data) => dialog === 'complete' ? action('complete-review', data) : dialog === 'reopen' ? action('reopen', data) : dialog === 'withdraw' ? action('withdraw-approval', data) : action(dialog === 'approval' ? 'approve' : 'reject', data)} />}
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
  // A reader with audit access can go from "누가 무엇을 했다" to the full
  // record -- what the value was before and after -- in one click.
  const { user } = useAuth()
  const auditable = user.roles.some(role => ['SYSTEM_ADMIN', 'AUDITOR'].includes(role))
  const [page, setPage] = useState<{ items: Record<string, unknown>[]; total: number; has_more: boolean }>()
  const [limit, setLimit] = useState(50)
  useEffect(() => { get<{ items: Record<string, unknown>[]; total: number; has_more: boolean }>(`/api/v1/review-requests/${reviewID}/history?limit=${limit}`).then(setPage).catch(e => toast.push(errorMessage(e), 'error')) }, [reviewID, limit])
  return <Modal title="심의 이력" onClose={onClose} footer={<>{page?.has_more && <Button onClick={() => setLimit(limit + 50)}>더 보기</Button>}<Button variant="primary" onClick={onClose}>닫기</Button></>}>
    {!page ? <Loading /> : page.items.length ? <>
      <p className="subtle">전체 {page.total}건 중 최근 {page.items.length}건. 감사로그에서 이 심의와 관련된 기록만 추린 것입니다.</p>
      <div className="table-wrap"><table><caption className="sr-only">심의 이력</caption>
        <thead><tr><th scope="col">시각</th><th scope="col">행위</th><th scope="col">수행자</th><th scope="col">대상</th></tr></thead>
        <tbody>{page.items.map((e, i) => <tr key={String(e.event_id || i)}><td>{formatDate(e.timestamp, true)}</td><td><Badge tone={e.result === 'SUCCESS' ? 'blue' : 'red'}>{String(e.event_label || e.event_type)}</Badge></td><td>{String(e.user_name || '-')}</td><td className="subtle">{auditable && e.target_id ? <Link className="table-link" to={`/admin/audit?target=${e.target_id}`} onClick={onClose}>{String(e.item_code || e.target_type || '')}</Link> : String(e.item_code || e.target_type || '')}</td></tr>)}</tbody>
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
function BulkReviewModal({ reviewID, itemIDs, count, people, onClose, onSaved }: { reviewID: string; itemIDs: string[]; count: number; people: DirectoryUser[]; onClose: () => void; onSaved: () => Promise<void> }) {
  const toast = useToast()
  const [form, setForm] = useState({ result: 'COMPLIANT', final_applicability: '', evidence_adequacy: '', opinion: '', overwrite: false })
  // The same gap found on ten items was ten separate change requests, written
  // ten times and delivered as ten notices for one piece of work.
  const [mode, setMode] = useState<'VERDICT' | 'CHANGE'>('VERDICT')
  const [change, setChange] = useState({ reason: '', due_date: '', assignee_id: '' })
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    setBusy(true)
    try {
      if (mode === 'CHANGE') {
        const out = await post<{ created: number; skipped: number }>(`/api/v1/review-requests/${reviewID}/change-requests/bulk`, { ...change, item_ids: itemIDs })
        toast.push(out.skipped ? `보완 요청 ${out.created}건을 등록했습니다. 이미 처리 중인 ${out.skipped}개는 건너뛰었습니다.` : `보완 요청 ${out.created}건을 등록했습니다.`)
      } else {
        const out = await post<{ applied: number; skipped: number }>(`/api/v1/review-requests/${reviewID}/review-results/bulk`, { ...form, item_ids: itemIDs })
        toast.push(out.skipped ? `${out.applied}개 항목을 판정했습니다. 이미 판정된 ${out.skipped}개는 건너뛰었습니다.` : `${out.applied}개 항목을 판정했습니다.`)
      }
      await onSaved()
    } catch (e) { toast.push(errorMessage(e), 'error') } finally { setBusy(false) }
  }
  return <Modal title={`선택한 ${count}개 항목 일괄 처리`} onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant="primary" disabled={busy || (mode === 'CHANGE' && (!change.reason.trim() || !change.due_date))} onClick={submit}>{mode === 'CHANGE' ? '보완 요청' : '판정 적용'}</Button></>}>
    <div className="toolbar"><button type="button" className={`chip ${mode === 'VERDICT' ? 'on' : ''}`} aria-pressed={mode === 'VERDICT'} onClick={() => setMode('VERDICT')}>일괄 판정</button><button type="button" className={`chip ${mode === 'CHANGE' ? 'on' : ''}`} aria-pressed={mode === 'CHANGE'} onClick={() => setMode('CHANGE')}>일괄 보완 요청</button></div>
    {mode === 'CHANGE' ? <>
      <div className="guide-block">같은 사유의 보완을 선택한 항목에 한 번에 등록합니다. 이미 처리 중인 보완 요청이 있는 항목은 건너뛰고, 작성자에게는 알림이 한 번만 갑니다.</div>
      <div className="form-grid">
        <Field label="보완 사유" required className="span-2"><LongText value={change.reason} onChange={v => setChange(x => ({ ...x, reason: v }))} /></Field>
        <Field label="완료 예정일" required help="기한이 없으면 알림도 지연 판정도 동작하지 않습니다."><input type="date" className="input" min={todayISO()} value={change.due_date} onChange={e => setChange(v => ({ ...v, due_date: e.target.value }))} /></Field>
        <Field label="조치 담당자" help="비우면 신청자에게 갑니다. 심의 참여자만 지정할 수 있습니다"><PeopleField value={change.assignee_id} people={people} onChange={id => setChange(v => ({ ...v, assignee_id: id }))} emptyLabel="신청자" /></Field>
      </div>
    </> : <>
    <div className="guide-block">같은 판정이 반복되는 항목을 한 번에 처리합니다. 결과는 감사로그에 일괄 판정으로 기록되며 개별 항목에서 다시 수정할 수 있습니다.</div>
    <div className="form-grid">
      <Field label="검토 결과" required><select className="select" value={form.result} onChange={e => setForm(v => ({ ...v, result: e.target.value }))}>{Object.entries(resultLabels).map(([code, label]) => <option key={code} value={code}>{label}</option>)}</select></Field>
      <Field label="최종 적용 여부" help="비우면 작성자 판단 유지"><select className="select" value={form.final_applicability} onChange={e => setForm(v => ({ ...v, final_applicability: e.target.value }))}><option value="">유지</option><option value="Y">Y</option><option value="N">N</option><option value="N/A">N/A</option></select></Field>
      <Field label="증적 충분성"><input className="input" value={form.evidence_adequacy} onChange={e => setForm(v => ({ ...v, evidence_adequacy: e.target.value }))} /></Field>
      <Field label="공통 의견" className="span-2"><LongText value={form.opinion} onChange={v => setForm(x => ({ ...x, opinion: v }))} /></Field>
      <label className="span-2"><input type="checkbox" checked={form.overwrite} onChange={e => setForm(v => ({ ...v, overwrite: e.target.checked }))} /> 이미 판정한 항목도 덮어쓰기</label>
    </div></>}
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
      <Field label="담당자" required help="심의에 참여하지 않는 사용자에게는 배정할 수 없습니다."><PeopleField value={form.assigned_to} people={people} onChange={id => setForm(v => ({ ...v, assigned_to: id }))} emptyLabel="지정 해제" withDepartment /></Field>
    </> : <>
    <div className="guide-block">같은 답변이 반복되는 항목을 한 번에 채웁니다. 결과는 감사로그에 일괄 작업으로 기록되며 개별 항목에서 다시 수정할 수 있습니다.</div>
    <div className="form-grid">
      <Field label="적용 여부" required><select className="select" value={form.applicability} onChange={e => setForm(v => ({ ...v, applicability: e.target.value }))}><option value="Y">Y</option><option value="N">N</option><option value="N/A">N/A</option></select></Field>
      <Field label="자체 판단"><select className="select" value={form.self_assessment} onChange={e => setForm(v => ({ ...v, self_assessment: e.target.value }))}><option value="">선택</option><option value="COMPLIANT">적합</option><option value="INSUFFICIENT">미흡</option><option value="N/A">N/A</option></select></Field>
      {form.applicability === 'N/A' && <Field label="공통 N/A 사유" required className="span-2"><LongText value={form.na_reason} onChange={v => setForm(x => ({ ...x, na_reason: v }))} /></Field>}
      <Field label="공통 현황" className="span-2"><LongText value={form.current_state} onChange={v => setForm(x => ({ ...x, current_state: v }))} /></Field>
      <Field label="담당자" help="함께 지정하려면 선택"><PeopleField value={form.assigned_to} people={people} onChange={id => setForm(v => ({ ...v, assigned_to: id }))} emptyLabel="변경 안 함" /></Field>
      <div className="span-2"><Toggle label="이미 작성된 항목도 덮어쓰기" value={form.overwrite} onChange={v => setForm(f => ({ ...f, overwrite: v }))} /></div>
    </div></>}
  </Modal>
}

type RuleCandidate = { source_item_id: string; assigned_item_id: string; template_name: string; item_code: string; title: string; category: string }
function RuleOverrideModal({reviewID,onClose,onSaved}:{reviewID:string;onClose:()=>void;onSaved:()=>Promise<void>}) { const toast=useToast(); const [candidates,setCandidates]=useState<RuleCandidate[]>(); const [action,setAction]=useState<'EXCLUDE'|'INCLUDE'>('EXCLUDE'); const [selected,setSelected]=useState(''); const [reason,setReason]=useState(''); useEffect(()=>{get<{items:RuleCandidate[]}>(`/api/v1/review-requests/${reviewID}/rule-candidates`).then(x=>setCandidates(x.items)).catch(e=>toast.push(errorMessage(e),'error'))},[reviewID]); const choices=(candidates||[]).filter(x=>action==='EXCLUDE'?Boolean(x.assigned_item_id):!x.assigned_item_id); useEffect(()=>setSelected(''),[action]); const submit=async()=>{const item=choices.find(x=>x.source_item_id===selected);if(!item)return;try{await post(`/api/v1/review-requests/${reviewID}/rule-overrides`,{action,source_item_id:item.source_item_id,item_id:item.assigned_item_id,reason});toast.push(action==='EXCLUDE'?'자동 배정 항목을 제외했습니다.':'체크리스트 항목을 수동 포함했습니다.');await onSaved();onClose()}catch(e){toast.push(errorMessage(e),'error')}}; return <Modal title="자동 배정 결과 조정" onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant="primary" disabled={!selected||!reason.trim()} onClick={submit}>변경 적용</Button></>}><div className="guide-block">최초 제출 전 자동 Rule 결과만 조정할 수 있으며, 수동 변경 사유와 작업자는 감사로그에 영구 기록됩니다.</div><div className="form-grid" data-sx="sx-036"><Field label="작업"><select className="select" value={action} onChange={e=>setAction(e.target.value as 'EXCLUDE'|'INCLUDE')}><option value="EXCLUDE">자동 배정에서 제외</option><option value="INCLUDE">미배정 항목 수동 포함</option></select></Field><Field label="체크리스트 항목" className="span-2" required><select className="select" value={selected} onChange={e=>setSelected(e.target.value)}><option value="">선택</option>{choices.map(x=><option key={x.source_item_id} value={x.source_item_id}>{x.template_name} · {x.item_code} · {x.title}</option>)}</select></Field><Field label="수동 변경 사유" className="span-2" required><LongText value={reason} onChange={setReason} /></Field></div></Modal> }

function ItemEditor({ review, item, reviewer, people, onSaved, onSelect }: { review: Review; item: ChecklistItem; reviewer: boolean; people: DirectoryUser[]; onSaved: () => Promise<void>; onSelect: () => void }) {
  const toast = useToast(); const editable = review.can_edit === true; const reviewable = review.can_review === true && review.status === 'REVIEWING'; const [draft, setDraft] = useState(() => responseFrom(item)); const [saved, setSaved] = useState(''); const [evidence, setEvidence] = useState<File[]>([]); const [uploading, setUploading] = useState(false); const [evidenceDescription, setEvidenceDescription] = useState(''); const [reviewResult, setReviewResult] = useState({ final_applicability: String(item.review_result.final_applicability || ''), result: String(item.review_result.result || ''), opinion: String(item.review_result.opinion || ''), evidence_adequacy: String(item.review_result.evidence_adequacy || ''), na_approved: item.review_result.na_approved as boolean | undefined, follow_up: String(item.review_result.follow_up || ''), follow_up_due_date: String(item.review_result.follow_up_due_date || '') }); const [changeOpen, setChangeOpen] = useState(false); const [pending, setPending] = useState(false); const [conflict, setConflict] = useState<Record<string, unknown>>(); const dirty = useRef(false); const timer = useRef<number | undefined>(undefined)
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
  const limits = useAuth().upload
  const tooBig = (file: File) => Boolean(limits?.max_size_mb) && file.size > Number(limits?.max_size_mb) * 1024 * 1024
  const wrongKind = (file: File) => { const allowed = limits?.allowed_extensions || []; if (!allowed.length) return false; const dot = file.name.lastIndexOf('.'); const ext = dot < 0 ? '' : file.name.slice(dot).toLowerCase(); return !allowed.some(a => a.toLowerCase() === ext || a.toLowerCase() === ext.replace('.', '')) }
  const uploadFile = async () => {
    if (!evidence.length) return
    // The server enforces these; checking here means a file that cannot be
    // accepted is refused now rather than after minutes of uploading it.
    const rejected = evidence.filter(file => tooBig(file) || wrongKind(file))
    if (rejected.length) {
      rejected.forEach(file => toast.push(tooBig(file) ? `${file.name}: 최대 ${limits?.max_size_mb}MB까지 업로드할 수 있습니다.` : `${file.name}: 허용되지 않는 확장자입니다 (${(limits?.allowed_extensions || []).join(', ')}).`, 'error'))
      return
    }
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
  // onFocusCapture is what makes this work for somebody using the keyboard:
  // clicking anywhere in the editor marks the item as the current one, and
  // tabbing into any of its fields has to do the same.
  return <div className="checklist-editor" onClick={onSelect} onFocusCapture={onSelect}><div className="form-grid"><Field label="적용 여부" required><div className="answer-pills">{['Y', 'N', 'N/A'].map(v => <button type="button" disabled={!editable} key={v} className={`answer-pill ${draft.applicability === v ? 'selected' : ''}`} onClick={() => set('applicability', v)}>{v}</button>)}</div></Field><Field label="자체 판단"><select className="select" disabled={!editable} value={draft.self_assessment} onChange={e => set('self_assessment', e.target.value)}><option value="">선택</option><option value="COMPLIANT">적합</option><option value="INSUFFICIENT">미흡</option><option value="N/A">N/A</option></select></Field>{!['YNNA','ASSESSMENT','FILE','GUIDE'].includes(item.answer_type) && <AnswerControl item={item} value={draft.answer} disabled={!editable} onChange={v=>set('answer',v)}/>} {draft.applicability === 'N/A' && <Field className="span-2" label="N/A 사유" required><LongText disabled={!editable} value={draft.na_reason} onChange={v => set('na_reason', v)} /></Field>}<Field className="span-2" label="현황 및 증적"><LongText disabled={!editable} placeholder="현재 적용 현황과 증적 위치를 구체적으로 작성하세요." value={draft.current_state} onChange={v => set('current_state', v)} /></Field><Field className="span-2" label="조치 계획"><LongText disabled={!editable} value={draft.action_plan} onChange={v => set('action_plan', v)} /></Field><Field label="담당자" help="이 심의에 참여하는 사람만 지정할 수 있습니다"><select className="select" disabled={!editable} value={draft.assigned_to} onChange={e => set('assigned_to', e.target.value)}><option value="">지정 안 함</option>{people.map(p => <option key={p.id} value={p.id}>{p.display_name}{p.department ? ` · ${p.department}` : ""}</option>)}</select></Field></div>{editable && <div data-sx="sx-012"><span className="save-state">{pending ? <span className="dirty-dot">저장되지 않은 변경</span> : saved ? <><Check size={13} /> {saved} 자동 저장</> : null}</span><Button small onClick={() => save()}><Save size={13} /> 지금 저장</Button></div>}
    <div data-sx="sx-002"><strong data-sx="sx-018">증적 첨부</strong>{editable && <div className="form-grid" data-sx="sx-028"><Field label="파일" help={evidence.length > 1 ? `${evidence.length}개 선택됨 · 각각 별도 증적으로 저장됩니다` : limits?.max_size_mb ? `여러 개를 한 번에 선택할 수 있습니다 · 파일당 최대 ${limits.max_size_mb}MB` : '여러 개를 한 번에 선택할 수 있습니다'}><input type="file" multiple className="input" accept={(limits?.allowed_extensions || []).map(x => x.startsWith('.') ? x : `.${x}`).join(',') || undefined} onChange={(e: ChangeEvent<HTMLInputElement>) => setEvidence(Array.from(e.target.files || []))} /></Field><Field label="설명"><input className="input" value={evidenceDescription} onChange={e => setEvidenceDescription(e.target.value)} /></Field><div><Button disabled={!evidence.length || uploading} onClick={uploadFile}><Upload size={14} /> {uploading ? '업로드 중…' : evidence.length > 1 ? `${evidence.length}건 암호화 업로드` : '암호화 업로드'}</Button></div></div>}{item.evidences.map(e => <EvidenceRow key={e.id} evidence={e} editable={editable} onSaved={onSaved} />)}{editable && <CarryOverEvidence reviewID={review.id} itemID={item.id} onCarried={onSaved} />}</div>
    {!reviewable && <ReviewVerdict result={item.review_result} onSaved={onSaved} />}
    {reviewable && answerChangedSinceReview(item) && <JudgedAnswer item={item} />}
    {(reviewable || editable) && <PreviousVerdicts reviewID={review.id} itemID={item.id} canEdit={editable} onCarried={onSaved} />}
    {(reviewable || editable) && <WhyThisItem reviewID={review.id} itemID={item.id} />}
    {reviewable && <div data-sx="sx-002"><strong data-sx="sx-018">보안 담당자 검토</strong><div className="form-grid" data-sx="sx-028"><Field label="최종 적용 여부"><select className="select" value={reviewResult.final_applicability} onChange={e => setReviewResult(v => ({ ...v, final_applicability: e.target.value }))}><option value="">작성자 판단 유지</option><option value="Y">Y</option><option value="N">N</option><option value="N/A">N/A</option></select></Field><Field label="검토 결과" required><select className="select" value={reviewResult.result} onChange={e => setReviewResult(v => ({ ...v, result: e.target.value }))}><option value="">선택</option><option value="COMPLIANT">적합</option><option value="CONDITIONAL">조건부 적합</option><option value="INSUFFICIENT">미흡</option><option value="NON_COMPLIANT">부적합</option><option value="NA_ACCEPTED">N/A 인정</option><option value="RECHECK">재확인</option></select></Field><Field label="증적 적정성"><select className="select" value={reviewResult.evidence_adequacy} onChange={e => setReviewResult(v => ({ ...v, evidence_adequacy: e.target.value }))}><option value="">선택</option><option value="ADEQUATE">적정</option><option value="PARTIAL">일부 보완</option><option value="INADEQUATE">부적정</option></select></Field><Field label="검토 의견" className="span-2"><LongText value={reviewResult.opinion} onChange={v => setReviewResult(x => ({ ...x, opinion: v }))} /></Field><Field label="후속조치" className="span-2"><LongText value={reviewResult.follow_up} onChange={v => setReviewResult(x => ({ ...x, follow_up: v }))} /></Field><Field label="조치 기한" required={Boolean(reviewResult.follow_up.trim())} help="후속조치를 적으면 기한이 필요합니다. 기한이 있어야 담당자에게 알림이 가고 지연 여부를 판정할 수 있습니다."><input type="date" className="input" min={todayISO()} value={reviewResult.follow_up_due_date} onChange={e => setReviewResult(v => ({ ...v, follow_up_due_date: e.target.value }))} /></Field></div><div data-sx="sx-009"><Button variant="danger" onClick={() => setChangeOpen(true)}><MessageSquareWarning size={14} /> 보완 요청</Button><Button variant="primary" onClick={saveReview}><ShieldCheck size={14} /> 검토 저장</Button></div></div>}
    {conflict && <ConflictModal conflict={conflict} onClose={() => setConflict(undefined)} onReload={async () => { setConflict(undefined); dirty.current = false; setPending(false); await onSaved() }} onOverwrite={async () => { await save(draft, true); await onSaved() }} />}
    {changeOpen && <ChangeRequestModal reviewID={review.id} itemID={item.id} onClose={() => setChangeOpen(false)} onSaved={onSaved} />}{item.change_requests.filter(c => c.status === 'OPEN' && editable).map(c => <ChangeAnswer key={c.id} change={c} onSaved={onSaved} />)}</div>
}

function EvidenceRow({evidence,editable,onSaved}:{evidence:ChecklistItem['evidences'][number];editable:boolean;onSaved:()=>Promise<void>}) { const toast=useToast(); const save=useDownload(); const [file,setFile]=useState<File>(); const [history,setHistory]=useState(false); const replace=async()=>{if(!file)return;const form=new FormData();form.append('file',file);try{await upload(`/api/v1/evidences/${evidence.id}/versions`,form);toast.push(`증적 v${evidence.current_version+1}을 등록했습니다.`);setFile(undefined);await onSaved()}catch(e){toast.push(errorMessage(e),'error')}};const remove=async()=>{if(!confirm(`${evidence.original_filename} 증적을 삭제할까요?`))return;try{await del(`/api/v1/evidences/${evidence.id}`);toast.push('증적을 논리 삭제했습니다.');await onSaved()}catch(e){toast.push(errorMessage(e),'error')}};return <div className="evidence-item"><FileCheck2 size={14}/><div data-sx="sx-017"><button type="button" className="table-link" onClick={() => save(`/api/v1/evidences/${evidence.id}/download`)}>{evidence.original_filename}</button><div className="subtle">{formatBytes(evidence.size_bytes)} · v{evidence.current_version}{(evidence as unknown as Record<string, unknown>).uploaded_by_name ? ` · ${(evidence as unknown as Record<string, unknown>).uploaded_by_name}` : ''} <ScanBadge status={evidence.scan_status} detail={String(evidence.scan_detail || '')} /></div></div><EvidencePreview evidence={evidence} />{evidence.current_version>1&&<Button small variant="ghost" title="버전 이력" onClick={()=>setHistory(true)}><History size={12}/> 이력</Button>}{editable&&<><input type="file" className="input" data-sx="sx-041" onChange={e=>setFile(e.target.files?.[0])}/><Button small disabled={!file} onClick={replace}><RefreshCw size={12}/> 새 버전</Button><Button small variant="danger" aria-label={`${evidence.original_filename} 증적 삭제`} onClick={remove}><Trash2 size={12}/></Button></>}{history&&<EvidenceHistory evidence={evidence} onClose={()=>setHistory(false)} />}</div>}

// A replaced file is still part of the record: the reviewer whose verdict rests
// on it has to be able to see what it was before, and read the earlier file.
function EvidenceHistory({evidence,onClose}:{evidence:ChecklistItem['evidences'][number];onClose:()=>void}) { const save=useDownload(); const toast=useToast(); const [items,setItems]=useState<Record<string,unknown>[]>(); useEffect(()=>{get<{items:Record<string,unknown>[]}>(`/api/v1/evidences/${evidence.id}/versions`).then(p=>setItems(p.items)).catch(e=>{toast.push(errorMessage(e),'error');setItems([])})},[]); const fetchVersion=(v:unknown,purged:boolean)=>{ if(purged){toast.push('보존 기간이 지나 파기된 버전입니다.','error');return} save(`/api/v1/evidences/${evidence.id}/download?version=${String(v)}`) }; return <Modal title={`${evidence.original_filename} 버전 이력`} onClose={onClose} footer={<Button onClick={onClose}>닫기</Button>}>{!items?<Loading/>:items.length?<div className="table-wrap"><table><thead><tr><th>버전</th><th>파일</th><th>크기</th><th>업로더</th><th>시각</th><th>SHA-256</th></tr></thead><tbody>{items.map(v=><tr key={String(v.version)}><td>v{String(v.version)} {Boolean(v.current)&&<Badge tone="green">현재</Badge>}{Boolean(v.purged)&&<Badge tone="red">파기됨</Badge>}</td><td><button type="button" className="table-link" onClick={()=>fetchVersion(v.version,Boolean(v.purged))}>{String(v.original_filename||'(이름 없음)')}</button></td><td>{formatBytes(Number(v.size_bytes))}</td><td>{String(v.uploaded_by||'-')}</td><td>{formatDate(String(v.created_at),true)}</td><td><code title={String(v.sha256)}>{String(v.sha256).slice(0,12)}…</code></td></tr>)}</tbody></table></div>:<Empty title="이력이 없습니다." description="이 증적은 교체된 적이 없습니다." />}</Modal> }

// The picker offers only accounts the service will accept -- active people who
// hold the requester role -- so a name that would be refused is never on it.
function HandoverModal({ reviewID, onClose, onSaved }: { reviewID: string; onClose: () => void; onSaved: () => Promise<void> }) {
  const toast = useToast()
  const [people, setPeople] = useState<DirectoryUser[]>([])
  const [chosen, setChosen] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { get<{ items: DirectoryUser[] }>('/api/v1/users/directory?role=REQUESTER').then(out => setPeople(out.items)).catch(() => undefined) }, [])
  const submit = async () => {
    setBusy(true)
    try { await post(`/api/v1/review-requests/${reviewID}/transfer-requester`, { requester_id: chosen }); toast.push('심의 요청자를 인계했습니다.'); await onSaved() }
    catch (e) { toast.push(errorMessage(e), 'error') } finally { setBusy(false) }
  }
  return <Modal title="심의 요청자 인계" onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant="primary" disabled={!chosen || busy} onClick={submit}>인계</Button></>}>
    <div className="guide-block">요청자는 이 심의를 취소할 수 있고, 보완 요청·승인·기한 알림이 기본으로 가는 사람입니다. 인계하면 이후 알림과 후속조치 안내가 넘겨받은 사람에게 갑니다.</div>
    <div className="form-grid"><Field label="넘겨받을 사람" required className="span-2" help="심의 요청 권한이 있는 활성 계정만 나옵니다"><PeopleField value={chosen} people={people} onChange={setChosen} emptyLabel="선택" withDepartment /></Field></div>
  </Modal>
}

// What the verdict was passed on. The item is already flagged as having moved
// on since it was judged; this is the half that was missing -- what it said
// then, so the reviewer can see what actually changed instead of re-reading
// the whole item and trusting their memory.
function JudgedAnswer({ item }: { item: ChecklistItem }) {
  const judged = (item.review_result as Record<string, unknown> | undefined)?.judged_answer as Record<string, unknown> | undefined
  if (!judged) return null
  const rows: [string, unknown, unknown][] = [
    ['적용 여부', judged.applicability, item.response.applicability],
    ['자체 판단', judged.self_assessment, item.response.self_assessment],
    ['현황 및 증적', judged.current_state, item.response.current_state],
    ['N/A 사유', judged.na_reason, item.response.na_reason],
    ['조치 계획', judged.action_plan, item.response.action_plan],
    ['증적 수', judged.evidence_count, item.evidences.length],
  ]
  const moved = rows.filter(([, before, after]) => String(before ?? '') !== String(after ?? ''))
  if (!moved.length) return null
  return <div data-sx="sx-002"><strong data-sx="sx-018">판정 이후 바뀐 내용</strong>
    <div className="table-wrap"><table><caption className="sr-only">판정 당시와 현재 답변 비교</caption>
      <thead><tr><th scope="col">항목</th><th scope="col">판정 당시</th><th scope="col">현재</th></tr></thead>
      <tbody>{moved.map(([label, before, after]) => <tr key={label}><th scope="row">{label}</th><td className="subtle">{String(before ?? '') || '-'}</td><td>{String(after ?? '') || '-'}</td></tr>)}</tbody>
    </table></div>
    <p className="subtle">이 항목은 판정 이후 위 내용이 바뀌었습니다. 다시 확인하고 `검토 저장`을 누르면 표시가 사라집니다.</p>
  </div>
}

// What was decided about this item the last time this service came through.
// The record was always there; finding it meant opening last year's review and
// scrolling to the same code, so in practice nobody did.
// The panel that says what was decided last time is also the only place that
// knows which files were attached last time, so the button that brings them
// forward belongs here rather than next to the upload control.

// The files attached to this item last time were reachable only through the
// previous-verdict panel, which appears only once an earlier review has judged
// the item. They belong beside the upload control, where somebody attaching
// evidence is already looking.
function CarryOverEvidence({ reviewID, itemID, onCarried }: { reviewID: string; itemID: string; onCarried: () => Promise<void> }) {
  const toast = useToast()
  const [rows, setRows] = useState<Record<string, unknown>[]>()
  const [busy, setBusy] = useState(false)
  const path = `/api/v1/review-requests/${reviewID}/items/${itemID}/evidences/carry-over`
  useEffect(() => { let alive = true; get<{ items: Record<string, unknown>[] }>(path).then(out => { if (alive) setRows(out.items) }).catch(() => undefined); return () => { alive = false } }, [path])
  if (!rows?.length) return null
  const carry = async () => {
    setBusy(true)
    try {
      const out = await post<{ copied: unknown[]; skipped: unknown[] }>(path, { evidence_ids: rows.map(x => String(x.id)) })
      toast.push(`증적 ${out.copied.length}건을 가져왔습니다.`)
      setRows([])
      await onCarried()
    } catch (e) { toast.push(errorMessage(e), 'error') } finally { setBusy(false) }
  }
  return <div className="guide-block" data-sx="sx-006">
    <div>같은 서비스의 이전 심의에 이 항목으로 첨부돼 있던 증적 {rows.length}건이 있습니다: {rows.map(x => String(x.original_filename)).join(', ')}</div>
    <Button small disabled={busy} onClick={carry}><Copy size={13} /> {busy ? '가져오는 중…' : '이전 증적 가져오기'}</Button>
  </div>
}


// The rule engine decides what a service is asked; the person answering could
// see that an item applied to them but never why. The answer is folded away
// until it is wanted, because most of the time it is not.
function WhyThisItem({ reviewID, itemID }: { reviewID: string; itemID: string }) {
  const [open, setOpen] = useState(false)
  const [why, setWhy] = useState<{ assigned_by: string; conditions?: Condition[]; override?: { reason: string; changed_by_name: string; changed_at: string } }>()
  useEffect(() => { if (!open) return; let alive = true; get<typeof why>(`/api/v1/review-requests/${reviewID}/items/${itemID}/why`).then(out => { if (alive) setWhy(out) }).catch(() => undefined); return () => { alive = false } }, [open, reviewID, itemID])
  return <div className="subtle" data-sx="sx-006">
    <button type="button" className="link-button" aria-expanded={open} onClick={() => setOpen(v => !v)}><HelpCircle size={13} /> 이 항목이 배정된 이유</button>
    {open && (!why ? <span> 불러오는 중…</span> : why.assigned_by === 'MANUAL'
      ? <div>담당자가 직접 포함한 항목입니다. {why.override?.reason}{why.override?.changed_by_name ? ` (${why.override.changed_by_name}, ${why.override.changed_at})` : ''}</div>
      : why.conditions?.length
        ? <ul>{why.conditions.map((c, i) => <li key={i}>{c.matched ? '✓' : '✗'} {c.negated ? '아님: ' : ''}{whyFieldLabels[c.field] || c.field} {whyOperators[c.operator] || c.operator} {whyValue(c.value)}{!c.matched && <> — 현재 {whyValue(c.actual)}</>}</li>)}</ul>
        : <div>이 분류의 서비스에는 조건 없이 항상 배정되는 항목입니다.</div>)}
  </div>
}
type Condition = { field: string; operator: string; value: unknown; actual: unknown; matched: boolean; negated: boolean }
const whyFieldLabels: Record<string, string> = {
  service_type: '서비스 유형', change_type: '변경 유형', exposure: '노출 구분', business_criticality: '업무 중요도',
  has_admin_page: '관리자 페이지 있음', processes_personal_data: '개인정보 처리', processes_credit_data: '신용정보 처리',
  external_customer_service: '대외 고객 서비스', uses_cloud: '클라우드 사용', uses_docker: 'Docker 사용',
  uses_kubernetes: 'Kubernetes 사용', external_integration: '외부 연계', internet_access: '인터넷 접점',
}
const whyOperators: Record<string, string> = { eq: '=', '=': '=', neq: '≠', '!=': '≠', in: '중 하나', contains: '포함', gt: '>', gte: '≥', lt: '<', lte: '≤', exists: '값 존재' }
const whyValue = (v: unknown) => typeof v === 'boolean' ? (v ? '예' : '아니오') : Array.isArray(v) ? v.join(', ') : String(v ?? '')

function PreviousVerdicts({ reviewID, itemID, canEdit, onCarried }: { reviewID: string; itemID: string; canEdit: boolean; onCarried: () => Promise<void> }) {
  const toast = useToast()
  const [rows, setRows] = useState<Record<string, unknown>[]>()
  const [busy, setBusy] = useState('')
  const [across, setAcross] = useState<Record<string, unknown>[]>([])
  useEffect(() => { let alive = true; get<{ items: Record<string, unknown>[]; across_services?: Record<string, unknown>[] }>(`/api/v1/review-requests/${reviewID}/items/${itemID}/verdict-history`).then(out => { if (alive) { setRows(out.items); setAcross(out.across_services || []) } }).catch(() => undefined); return () => { alive = false } }, [reviewID, itemID])
  const carry = async (row: Record<string, unknown>, key: string) => {
    const files = (row.evidence || []) as { id: string }[]
    setBusy(key)
    try {
      const out = await post<{ copied: unknown[]; skipped: { filename: string; reason: string }[] }>(`/api/v1/review-requests/${reviewID}/items/${itemID}/evidences/carry-over`, { evidence_ids: files.map(f => f.id) })
      toast.push(out.skipped?.length ? `증적 ${out.copied.length}건을 가져왔습니다. ${out.skipped.length}건은 가져오지 못했습니다.` : `증적 ${out.copied.length}건을 가져왔습니다.`)
      await onCarried()
    } catch (e) { toast.push(errorMessage(e), 'error') } finally { setBusy('') }
  }
  // The same requirement is judged on every service that gets it, and holding
  // two services to different standards on one control is exactly what nobody
  // can notice from inside a single review.
  const others = across.length ? <div data-sx="sx-002"><strong data-sx="sx-018">다른 서비스의 판정 ({across.length})</strong>
    {across.map((row, i) => <div className="change-item" key={`x-${i}`}>
      <Link className="table-link" to={`/reviews/${String(row.review_id)}`}>{String(row.review_number)}</Link> <strong>{String(row.service_name)}</strong>
      <Badge tone={['INSUFFICIENT', 'NON_COMPLIANT'].includes(String(row.result)) ? 'red' : String(row.result) === 'CONDITIONAL' ? 'amber' : 'green'}>{resultText[String(row.result)] || String(row.result)}</Badge>
      <span className="subtle"> {String(row.decided_on || '')}{row.reviewer_name ? ` · ${String(row.reviewer_name)}` : ''}</span>
      {row.opinion ? <p>{String(row.opinion)}</p> : null}
      {row.follow_up ? <div className="subtle">후속조치: {String(row.follow_up)}</div> : null}
    </div>)}
  </div> : null
  if (!rows?.length) return others
  return <div data-sx="sx-002"><strong data-sx="sx-018">이전 심의 판정 ({rows.length})</strong>
    {rows.map((row, i) => <div className="change-item" key={i}>
      <Link className="table-link" to={`/reviews/${String(row.review_id)}`}>{String(row.review_number)}</Link>
      <Badge tone={['INSUFFICIENT', 'NON_COMPLIANT'].includes(String(row.result)) ? 'red' : String(row.result) === 'CONDITIONAL' ? 'amber' : 'green'}>{resultText[String(row.result)] || String(row.result)}</Badge>
      <span className="subtle"> {String(row.decided_on || '')}{row.reviewer_name ? ` · ${String(row.reviewer_name)}` : ''}</span>
      {row.opinion ? <p>{String(row.opinion)}</p> : null}
      {row.follow_up ? <div className="subtle">후속조치: {String(row.follow_up)}</div> : null}
      {Array.isArray(row.evidence_names) && row.evidence_names.length > 0 ? <div className="subtle">그때 첨부한 증적: {(row.evidence_names as string[]).join(', ')}
        {canEdit && Array.isArray(row.evidence) && (row.evidence as unknown[]).length > 0 ? <> <Button small disabled={busy === String(i)} onClick={() => carry(row, String(i))}><Copy size={13} /> {busy === String(i) ? '가져오는 중…' : `이 증적 ${(row.evidence as unknown[]).length}건 가져오기`}</Button></> : null}</div> : null}
    </div>)}
    {others}
  </div>
}

const resultText: Record<string, string> = { COMPLIANT: '적합', CONDITIONAL: '조건부 적합', INSUFFICIENT: '미흡', NON_COMPLIANT: '부적합', NA_ACCEPTED: 'N/A 인정', RECHECK: '재확인' }

function ChangeRequestModal({ reviewID, itemID, onClose, onSaved }: { reviewID: string; itemID: string; onClose: () => void; onSaved: () => Promise<void> }) { const toast = useToast(); const [reason, setReason] = useState(''); const [due, setDue] = useState(''); const submit = async () => { try { await post(`/api/v1/review-requests/${reviewID}/change-requests`, { item_id: itemID, reason, due_date: due, assignee_id: '' }); toast.push('보완 요청을 등록했습니다.'); onClose(); await onSaved() } catch (e) { toast.push(errorMessage(e), 'error') } }; return <Modal title="항목 보완 요청" onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant="danger" disabled={!reason} onClick={submit}>보완 요청</Button></>}><div className="form-grid"><Field label="보완 사유" required className="span-2"><LongText value={reason} onChange={setReason} /></Field><Field label="완료 예정일" required help="기한이 있어야 담당자에게 알림이 가고 지연 여부를 판정할 수 있습니다."><input type="date" className="input" min={todayISO()} value={due} onChange={e => setDue(e.target.value)} /></Field></div></Modal> }
function ChangeAnswer({ change, onSaved }: { change: ChangeRequest; onSaved: () => Promise<void> }) { const toast = useToast(); const [answer, setAnswer] = useState(change.answer || ''); const submit = async () => { try { await api(`/api/v1/change-requests/${change.id}`, { method: 'PATCH', body: JSON.stringify({ answer, status: 'DONE' }) }); toast.push('보완 조치를 완료했습니다.'); await onSaved() } catch (e) { toast.push(errorMessage(e), 'error') } }; return <div className="change-item"><Badge tone="amber">보완 요청</Badge><p>{change.reason}</p><LongText placeholder="조치 내용" value={answer} onChange={setAnswer} /><Button small variant="primary" onClick={submit}>조치 완료</Button></div> }
function CommentBox({reviewID,item,onSaved}:{reviewID:string;item:ChecklistItem;onSaved:()=>Promise<void>}){const toast=useToast();const[body,setBody]=useState('');const submit=async()=>{try{await post(`/api/v1/review-requests/${reviewID}/items/${item.id}/comments`,{body});setBody('');await onSaved()}catch(e){toast.push(errorMessage(e),'error')}};return <><h4>항목 코멘트 ({item.comments?.length||0})</h4>{item.comments?.map(c=><div className="change-item" key={c.id}><strong>{c.author_name}</strong><div className="subtle">{formatDate(c.created_at,true)}</div><p>{c.body}</p></div>)}<LongText placeholder="작성자와 검토자가 함께 보는 코멘트" value={body} onChange={setBody} /><Button small disabled={!body.trim()} onClick={submit}><MessageSquareWarning size={13}/> 코멘트 등록</Button></>}
function AnswerControl({item,value,disabled,onChange}:{item:ChecklistItem;value:unknown;disabled:boolean;onChange:(v:unknown)=>void}){const options=(item.options||[]).map(x=>typeof x==='string'?x:String((x as Record<string,unknown>).label||(x as Record<string,unknown>).value||''));const scalar=typeof value==='object'&&value!==null?'value'in value?String((value as Record<string,unknown>).value??''):'' : String(value??'');if(item.answer_type==='MULTI_SELECT'){const selected=Array.isArray((value as Record<string,unknown>)?.values)?(value as Record<string,unknown>).values as string[]:[];return <Field className="span-2" label="다중 선택"><div className="answer-pills">{options.map(x=><label className={`answer-pill ${selected.includes(x)?'selected':''}`} key={x}><input type="checkbox" disabled={disabled} checked={selected.includes(x)} onChange={e=>onChange({values:e.target.checked?[...selected,x]:selected.filter(v=>v!==x)})}/> {x}</label>)}</div></Field>};if(item.answer_type==='REPEAT_TABLE'){const rows=Array.isArray((value as Record<string,unknown>)?.rows)?(value as Record<string,unknown>).rows as string[]:[];return <Field className="span-2" label="반복 목록"><div>{rows.map((row,i)=><div data-sx="sx-015" key={i}><input className="input" disabled={disabled} value={row} onChange={e=>onChange({rows:rows.map((v,n)=>n===i?e.target.value:v)})}/><Button small variant="danger" disabled={disabled} onClick={()=>onChange({rows:rows.filter((_,n)=>n!==i)})}>삭제</Button></div>)}<Button small disabled={disabled} onClick={()=>onChange({rows:[...rows,'']})}>행 추가</Button></div></Field>};if(item.answer_type==='SINGLE_SELECT')return <Field className="span-2" label="선택 답변"><select className="select" disabled={disabled} value={scalar} onChange={e=>onChange({value:e.target.value})}><option value="">선택</option>{options.map(x=><option key={x}>{x}</option>)}</select></Field>;if(item.answer_type==='USER')return <UserAnswer value={scalar} disabled={disabled} onChange={v=>onChange({value:v})}/>;if(item.answer_type==='LONG_TEXT')return <Field className="span-2" label="상세 답변"><textarea className="textarea" disabled={disabled} value={scalar} onChange={e=>onChange({value:e.target.value})}/></Field>;const type=item.answer_type==='NUMBER'?'number':item.answer_type==='DATE'?'date':item.answer_type==='URL'?'url':'text';return <Field className="span-2" label="항목 답변"><input className="input" type={type} disabled={disabled} value={scalar} onChange={e=>onChange({value:type==='number'?(e.target.value===''?'':Number(e.target.value)):e.target.value})}/></Field>}
function UserAnswer({value,disabled,onChange}:{value:string;disabled:boolean;onChange:(v:string)=>void}){const[users,setUsers]=useState<DirectoryUser[]>([]);useEffect(()=>{directory<DirectoryUser>().then(setUsers).catch(()=>undefined)},[]);return <Field className="span-2" label="담당자"><select className="select" disabled={disabled} value={value} onChange={e=>onChange(e.target.value)}><option value="">선택</option>{users.map(u=><option key={u.id} value={u.id}>{u.display_name} · {u.department||u.username}</option>)}</select></Field>}
// The final opinion is written from scratch at the end of a few hundred
// judgements, and what it has to say first is what the judgements were. The
// counts are already known, so the box opens with them written out; the
// reviewer edits or replaces the text, and nothing is submitted unread.
function completionDraft(items: ChecklistItem[], results: Record<string, number>): string {
  const findings = items.filter(x => ['INSUFFICIENT', 'NON_COMPLIANT', 'CONDITIONAL', 'RECHECK'].includes(flagsOf(x).result))
  const lines = [`총 ${items.length}개 항목 중 적합 ${results.compliant || 0}건, 조건부 ${results.conditional || 0}건, 미흡·부적합 ${(results.insufficient || 0) + (results.non_compliant || 0)}건, N/A ${results.na || 0}건입니다.`]
  if (findings.length) {
    lines.push('', '지적 항목:')
    findings.slice(0, 10).forEach(x => lines.push(`- ${x.item_code} ${x.title}: ${resultText[flagsOf(x).result] || flagsOf(x).result}`))
    if (findings.length > 10) lines.push(`- 외 ${findings.length - 10}건`)
  }
  const followUps = Number(results.follow_up || 0)
  if (followUps) lines.push('', `후속조치 ${followUps}건은 기한 내 이행 여부를 별도로 확인합니다.`)
  return lines.join('\n')
}

// What the counts imply, offered as the pre-selected result rather than always
// starting at 승인.
function suggestedResult(results: Record<string, number>): string {
  if ((results.insufficient || 0) + (results.non_compliant || 0) > 0) return 'REJECTED'
  if ((results.conditional || 0) > 0 || (results.follow_up || 0) > 0) return 'CONDITIONAL'
  return 'APPROVED'
}

function DecisionModal({ kind, busy, draft, suggested, onClose, onSubmit }: { kind: 'complete' | 'approval' | 'reject' | 'reopen' | 'withdraw'; busy: boolean; draft?: string; suggested?: string; onClose: () => void; onSubmit: (data: unknown) => void }) { const [comment, setComment] = useState(draft || ''); const [result, setResult] = useState(suggested || 'APPROVED'); const complete = kind === 'complete'; return <Modal title={complete ? '검토 완료' : kind === 'approval' ? '최종 승인' : '심의 반려'} onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant={kind === 'reject' ? 'danger' : 'primary'} disabled={busy || ((kind === 'reopen' || kind === 'withdraw') && !comment.trim())} onClick={() => onSubmit(complete ? { final_opinion: comment, final_result: result } : { comment })}>{complete ? '검토 완료' : kind === 'approval' ? '승인' : '반려'}</Button></>}><div className="form-grid">{complete && <Field label="심의 결과"><select className="select" value={result} onChange={e => setResult(e.target.value)}><option value="APPROVED">승인</option><option value="CONDITIONAL">조건부 승인</option><option value="REJECTED">반려</option></select></Field>}<Field label={complete ? '최종 의견' : '의견'} className="span-2"><LongText value={comment} onChange={setComment} /></Field></div></Modal> }

// The verdict used to be visible only inside the panel the reviewer edits it
// in, which needs the review to be under review and the reader to be the
// reviewer. So the person whose service it is never saw why an item was
// judged as it was, nor the action they were being asked to take -- and a
// reminder about that action linked them to a page that did not show it.
function ReviewVerdict({ result, onSaved }: { result: Record<string, unknown>; onSaved: () => Promise<void> }) {
  const toast = useToast()
  const [reporting, setReporting] = useState(false)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const report = async () => {
    setBusy(true)
    try {
      await post(`/api/v1/review-results/${String(result.id)}/follow-up`, { action: 'report', note })
      toast.push('조치 완료를 보고했습니다. 보안 담당자 확인 후 종료됩니다.')
      setReporting(false)
      await onSaved()
    } catch (e) { toast.push(errorMessage(e), 'error') } finally { setBusy(false) }
  }
  const verdict = String(result?.result || '')
  const opinion = String(result?.opinion || '')
  const action = String(result?.follow_up || '')
  if (!verdict && !opinion && !action) return null
  const due = String(result?.follow_up_due_date || '').slice(0, 10)
  const doneOn = String(result?.follow_up_done_at || '').slice(0, 10)
  const late = Boolean(due) && !doneOn && due < new Date().toISOString().slice(0, 10)
  return <>
  <div data-sx="sx-002">
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
        {/* The team that did the work says so here; the security side accepts
            it from the register. Before this they had nowhere to report it. */}
        {!doneOn && (result?.follow_up_reported_at
          ? <span className="badge blue">조치 보고됨 · 보안 담당자 확인 대기</span>
          : <Button small onClick={() => { setReporting(true); setNote('') }}>조치 완료 보고</Button>)}
      </Field>}
    </div>
  </div>
  {reporting && <Modal title="조치 완료 보고" onClose={() => setReporting(false)}
    footer={<><Button onClick={() => setReporting(false)}>취소</Button><Button variant="primary" disabled={busy || !note.trim()} onClick={report}>보고</Button></>}>
    <div className="guide-block">{action}</div>
    <Field label="조치 내용" required><LongText value={note} onChange={setNote} /></Field>
  </Modal>}
  </>
}

const verdictLabel: Record<string, string> = { COMPLIANT: '적합', CONDITIONAL: '조건부 적합', INSUFFICIENT: '미흡', NON_COMPLIANT: '부적합', NA_ACCEPTED: 'N/A 인정', RECHECK: '재확인' }
const verdictTone: Record<string, 'green' | 'amber' | 'red' | ''> = { COMPLIANT: 'green', CONDITIONAL: 'amber', INSUFFICIENT: 'amber', NON_COMPLIANT: 'red', RECHECK: 'amber' }

// The closing statement of the whole review -- what it was decided to be and
// why -- was recorded and then shown nowhere. A requester whose review came
// back rejected had no way to read the reason short of exporting the file.
// The user guide has always described adding a co-author or a read-only
// participant to a review. The endpoint existed; the screen did not, so the
// only way to do it was to call the API by hand -- and there was no way at all
// to see who had been given access.
function ReviewParticipants({ reviewID, editable, onSaved }: { reviewID: string; editable: boolean; onSaved?: () => Promise<void> | void }) {
  const toast = useToast()
  type Participant = { user_id: string; display_name: string; department: string; active: boolean; participant_role: string }
  const [people, setPeople] = useState<Participant[]>()
  const [directoryUsers, setDirectoryUsers] = useState<DirectoryUser[]>([])
  const [adding, setAdding] = useState(false)
  const [choice, setChoice] = useState({ user_id: '', role: 'CONTRIBUTOR' })
  const load = () => get<Participant[]>(`/api/v1/review-requests/${reviewID}/participants`).then(setPeople).catch(() => setPeople([]))
  useEffect(() => { load(); directory<DirectoryUser>().then(setDirectoryUsers).catch(() => undefined) }, [reviewID])
  const add = async () => {
    if (!choice.user_id) return
    try { const out = await post<{ released_items?: number }>(`/api/v1/review-requests/${reviewID}/participants`, choice); const released = Number(out?.released_items || 0); toast.push(released ? `참여자를 저장하고 담당 항목 ${released}개의 담당자를 비웠습니다.` : '참여자를 추가했습니다.'); setAdding(false); setChoice({ user_id: '', role: 'CONTRIBUTOR' }); await load(); await onSaved?.() }
    catch (e) { toast.push(errorMessage(e), 'error') }
  }
  const remove = async (person: Participant) => {
    if (!confirm(`${person.display_name} 참여자를 해제할까요?`)) return
    // Releasing their items is part of the removal, so the toast says how many
    // are now waiting for a new owner rather than leaving that to be noticed.
    try { const out = await del<{ released_items?: number }>(`/api/v1/review-requests/${reviewID}/participants/${person.user_id}`); const released = Number(out?.released_items || 0); toast.push(released ? `참여자를 해제하고 담당 항목 ${released}개의 담당자를 비웠습니다.` : '참여자를 해제했습니다.'); await load(); await onSaved?.() }
    catch (e) { toast.push(errorMessage(e), 'error') }
  }
  if (!people) return null
  if (!people.length && !editable) return null
  return <section className="card"><div className="card-header"><h3>참여자</h3><Badge>{people.length}</Badge>{editable && <div className="header-actions"><Button small onClick={() => setAdding(true)}><UserRound size={13} /> 참여자 추가</Button></div>}</div>
    {people.length ? <div className="table-wrap"><table><thead><tr><th scope="col">이름</th><th scope="col">부서</th><th scope="col">권한</th>{editable && <th scope="col"></th>}</tr></thead>
      <tbody>{people.map(person => <tr key={person.user_id}><td>{person.display_name}{!person.active && <> <Badge tone="red">비활성</Badge></>}</td><td className="subtle">{person.department || '-'}</td>
        <td><Badge tone={person.participant_role === 'CONTRIBUTOR' ? 'blue' : ''}>{person.participant_role === 'CONTRIBUTOR' ? '작성 가능' : '열람 전용'}</Badge></td>
        {editable && <td><Button small variant="danger" onClick={() => remove(person)}>해제</Button></td>}</tr>)}</tbody></table></div>
      : <div className="card-body"><p className="subtle">이 심의에는 신청자 외의 참여자가 없습니다.</p></div>}
    {adding && <Modal title="참여자 추가" onClose={() => setAdding(false)} footer={<><Button onClick={() => setAdding(false)}>취소</Button><Button variant="primary" disabled={!choice.user_id} onClick={add}>추가</Button></>}>
      <div className="form-grid">
        <Field label="사용자" required className="span-2"><PeopleField value={choice.user_id} people={directoryUsers} onChange={id => setChoice(v => ({ ...v, user_id: id }))} emptyLabel="선택" withDepartment /></Field>
        <Field label="권한" help="열람 전용 참여자는 심의와 증적을 볼 수 있지만 체크리스트를 수정하거나 항목을 배정받을 수 없습니다."><select className="select" value={choice.role} onChange={e => setChoice(v => ({ ...v, role: e.target.value }))}><option value="CONTRIBUTOR">작성 가능</option><option value="VIEWER">열람 전용</option></select></Field>
      </div></Modal>}
  </section>
}


// What the approver is being asked to sign: the findings behind the
// conclusion, the promises made to earn it, and the work the service still
// owes. It sits above the two buttons that end the review.
function ApprovalBrief({ reviewID }: { reviewID: string }) {
  const [brief, setBrief] = useState<{ findings: Record<string, unknown>[]; follow_ups: Record<string, unknown>[]; unverified_changes: number; follow_ups_without_due_date: number }>()
  useEffect(() => { let alive = true; get<typeof brief>(`/api/v1/review-requests/${reviewID}/approval-brief`).then(out => { if (alive) setBrief(out) }).catch(() => undefined); return () => { alive = false } }, [reviewID])
  if (!brief) return null
  const nothing = !brief.findings.length && !brief.follow_ups.length && !brief.unverified_changes
  return <section className="card">
    <div className="card-header"><h2><ShieldCheck size={17} /> 결재 전 확인</h2>
      <Badge tone={brief.findings.length ? 'amber' : 'green'}>지적 {brief.findings.length}건</Badge>
      <Badge tone={brief.unverified_changes ? 'red' : ''}>미검증 보완 {brief.unverified_changes}건</Badge></div>
    <div className="card-body">
      {nothing ? <p className="subtle">지적 항목과 약속된 후속조치가 없습니다.</p> : null}
      {brief.findings.length > 0 && <><strong>지적 항목</strong>
        <ul>{brief.findings.map((f, i) => <li key={`f-${i}`}><code>{String(f.item_code)}</code> {String(f.title)} — <Badge tone={['INSUFFICIENT', 'NON_COMPLIANT'].includes(String(f.result)) ? 'red' : 'amber'}>{resultText[String(f.result)] || String(f.result)}</Badge>{f.opinion ? <span className="subtle"> {String(f.opinion)}</span> : null}</li>)}</ul></>}
      {brief.follow_ups.length > 0 && <><strong>승인 시 남는 후속조치</strong>
        <ul>{brief.follow_ups.map((f, i) => <li key={`u-${i}`}><code>{String(f.item_code)}</code> {String(f.follow_up)} {f.due_date ? <span className="subtle">· 기한 {String(f.due_date)}</span> : <Badge tone="red">기한 없음 · 알림이 가지 않습니다</Badge>}</li>)}</ul></>}
      {brief.unverified_changes > 0 && <p className="subtle">아직 확인되지 않은 보완 요청이 {brief.unverified_changes}건 있습니다.</p>}
    </div>
  </section>
}

function ReviewOutcome({ review }: { review: Review }) {
  const result = String((review as unknown as Record<string, unknown>).final_result || '')
  const opinion = String((review as unknown as Record<string, unknown>).final_opinion || '')
  const decisions = ((review as unknown as Record<string, unknown>).decisions || []) as Record<string, unknown>[]
  if (!result && !opinion && !decisions.length) return null
  return <section className="card">
    <div className="card-header"><h2><FileCheck2 size={17} /> 심의 결론</h2>
      {result && <Badge tone={result === 'REJECTED' ? 'red' : result === 'CONDITIONAL' ? 'amber' : 'green'}>{outcomeLabel[result] || result}</Badge>}</div>
    <div className="card-body">
      {opinion && <><strong>최종 의견</strong><p className="subtle">{opinion}</p></>}
      {decisions.map((decision, i) => <div className="change-item" key={i}>
        <Badge tone={decision.decision === 'REJECTED' ? 'red' : 'green'}>{decision.decision === 'REJECTED' ? '반려' : '승인'}</Badge>
        <span className="subtle"> {String(decision.approver_name || '')} · {formatDate(String(decision.decided_at || ''), true)}</span>
        {decision.comment ? <p>{String(decision.comment)}</p> : null}
      </div>)}
    </div>
  </section>
}

const outcomeLabel: Record<string, string> = { APPROVED: '승인', CONDITIONAL: '조건부 승인', REJECTED: '반려' }

// When a review was submitted and when it was decided are part of its record
// -- the exported file has carried them all along, the screen never did. An
// auditor reading a review on screen could not say when it happened.
function ReviewDates({ review }: { review: Review }) {
  const value = (key: string) => String((review as unknown as Record<string, unknown>)[key] || '')
  const parts: string[] = []
  const submitted = value('first_submitted_at')
  const resubmitted = value('final_submitted_at')
  const approved = value('approved_at')
  if (submitted) parts.push(`제출 ${formatDate(submitted)}`)
  if (resubmitted && resubmitted.slice(0, 10) !== submitted.slice(0, 10)) parts.push(`최종 제출 ${formatDate(resubmitted)}`)
  if (approved) parts.push(`승인 ${formatDate(approved)}`)
  if (!parts.length) return <>아직 제출되지 않았습니다.</>
  return <>{parts.join(' · ')}</>
}
