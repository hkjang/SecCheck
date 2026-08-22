import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, ChevronLeft, ChevronRight, Download, Filter, Plus, RotateCcw, Search, ShieldCheck } from 'lucide-react'
import { directory, get } from '../lib/api'
import { DirectoryUser, Page, Review } from '../lib/types'
import { Badge, Button, Empty, Field, Loading, StatusBadge, formatDate, useDownload } from '../components/ui'

const emptyFilter = { q: '', status: '', department: '', reviewer_id: '', from: '', to: '', overdue: '', mine: '' }
const sorts: [string, string][] = [['updated', '최근 변경순'], ['created', '생성일순'], ['open_date', '오픈 예정일순'], ['number', '심의번호순'], ['service', '서비스명순'], ['status', '상태순']]

export default function Reviews({ security = false }: { security?: boolean }) {
  const save = useDownload()
  const [page, setPage] = useState<Page<Review>>()
  const [filter, setFilter] = useState({ ...emptyFilter, status: security ? 'SUBMITTED,RESUBMITTED' : '' })
  const [sort, setSort] = useState(security ? 'open_date' : 'updated')
  const [offset, setOffset] = useState(0)
  const [limit, setLimit] = useState(50)
  const [people, setPeople] = useState<DirectoryUser[]>([])
  const params = useMemo(() => {
    const qs = new URLSearchParams({ sort, limit: String(limit), offset: String(offset) })
    Object.entries(filter).forEach(([k, v]) => { if (v) qs.set(k, v) })
    return qs
  }, [filter, sort, limit, offset])
  useEffect(() => { directory<DirectoryUser>().then(setPeople).catch(() => undefined) }, [])
  useEffect(() => { setPage(undefined); const timer = window.setTimeout(() => { get<Page<Review>>(`/api/v1/review-requests?${params}`).then(setPage) }, 180); return () => clearTimeout(timer) }, [params])
  const set = (key: keyof typeof filter, value: string) => { setOffset(0); setFilter(v => ({ ...v, [key]: value })) }
  const dirty = Object.entries(filter).some(([k, v]) => v !== (emptyFilter as Record<string, string>)[k])
  const shown = page?.items || []
  const from = page && page.total ? offset + 1 : 0
  return <div className="page">
    <div className="page-header"><div><h1 className="page-title">{security ? '보안 검토 Queue' : '심의 목록'}</h1><p className="page-description">{security ? '제출·재제출된 건을 시작하고 항목별 검토를 진행하세요.' : '권한이 있는 심의 건만 표시됩니다.'}</p></div><div className="header-actions"><Button onClick={() => save(`/api/v1/review-requests?${new URLSearchParams({ ...Object.fromEntries(params), format: 'csv' })}`)}><Download size={14} /> CSV</Button>{!security && <Link to="/reviews/new"><Button variant="primary"><Plus size={15} /> 신규 심의</Button></Link>}</div></div>
    <div className="card"><div className="card-body">
      <div className="toolbar"><div className="search-box"><Search /><input className="input" aria-label="심의 검색" placeholder="심의번호, 서비스명, 부서 검색" value={filter.q} onChange={e => set('q', e.target.value)} /></div>
        <Filter size={16} color="#6d7a8e" aria-hidden="true" />
        <select className="select" aria-label="상태 필터" value={filter.status} onChange={e => set('status', e.target.value)}><option value="">전체 상태</option><option value="DRAFT">작성 중</option><option value="SUBMITTED,RESUBMITTED">제출·재제출</option><option value="REVIEWING">검토 중</option><option value="CHANGE_REQUESTED">보완 요청</option><option value="APPROVAL_PENDING">승인 대기</option><option value="APPROVED">심의 완료</option><option value="REJECTED">반려</option><option value="CLOSED">종료</option></select>
        <select className="select" aria-label="정렬" value={sort} onChange={e => { setOffset(0); setSort(e.target.value) }}>{sorts.map(([v, label]) => <option key={v} value={v}>{label}</option>)}</select>
        <button type="button" className={`chip ${filter.mine ? 'on' : ''}`} aria-pressed={Boolean(filter.mine)} onClick={() => set('mine', filter.mine ? '' : '1')}>내 차례</button>
        <button type="button" className={`chip ${filter.overdue ? 'on' : ''}`} aria-pressed={Boolean(filter.overdue)} onClick={() => set('overdue', filter.overdue ? '' : '1')}><AlertTriangle size={13} /> 기한 초과</button>
        {dirty && <Button small onClick={() => { setOffset(0); setFilter({ ...emptyFilter }) }}><RotateCcw size={13} /> 초기화</Button>}
      </div>
      <div className="form-grid compact">
        <Field label="담당 부서"><input className="input" value={filter.department} onChange={e => set('department', e.target.value)} /></Field>
        <Field label="보안 담당자"><select className="select" value={filter.reviewer_id} onChange={e => set('reviewer_id', e.target.value)}><option value="">전체</option>{people.map(p => <option key={p.id} value={p.id}>{p.display_name}</option>)}</select></Field>
        <Field label="생성일 시작"><input type="date" className="input" max={filter.to || undefined} value={filter.from} onChange={e => set('from', e.target.value)} /></Field>
        <Field label="생성일 종료"><input type="date" className="input" min={filter.from || undefined} value={filter.to} onChange={e => set('to', e.target.value)} /></Field>
      </div>
    </div>
      {!page ? <Loading /> : shown.length ? <><div className="table-wrap"><table><caption className="sr-only">심의 목록</caption><thead><tr><th scope="col">심의번호</th><th scope="col">서비스</th><th scope="col">유형</th><th scope="col">담당 부서</th><th scope="col">요청자 / 검토자</th><th scope="col">보완</th><th scope="col">오픈 예정</th><th scope="col">상태</th><th scope="col"><span className="sr-only">작업</span></th></tr></thead>
        <tbody>{shown.map(item => <tr key={item.id}><td><Link className="table-link" to={`/reviews/${item.id}`}>{item.review_number}</Link></td><td><strong>{item.service_name}</strong></td><td>{item.service_type} · {item.change_type}</td><td>{item.department}</td><td>{String(item.requester_name || '-')}<div className="subtle">{String(item.reviewer_name || '미배정')}</div></td><td>{item.open_change_requests ? <Badge tone={item.overdue_change_requests ? 'red' : 'amber'}>{item.open_change_requests}건{item.overdue_change_requests ? ` · 초과 ${item.overdue_change_requests}` : ''}</Badge> : <span className="subtle">-</span>}</td><td>{formatDate(item.planned_open_date)}</td><td><StatusBadge status={item.status} /></td><td><Link to={`/reviews/${item.id}`}><Button small>{security ? <><ShieldCheck size={14} /> 검토</> : '상세'}</Button></Link></td></tr>)}</tbody></table></div>
        <div className="card-body pager"><span className="subtle">{page.total}건 중 {from}–{offset + shown.length}</span><div className="header-actions"><select className="select" aria-label="페이지 크기" value={limit} onChange={e => { setOffset(0); setLimit(Number(e.target.value)) }}>{[25, 50, 100, 200].map(n => <option key={n} value={n}>{n}개씩</option>)}</select><Button small disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}><ChevronLeft size={14} /> 이전</Button><Button small disabled={!page.has_more} onClick={() => setOffset(offset + limit)}>다음 <ChevronRight size={14} /></Button></div></div></> : <Empty title="조건에 맞는 심의가 없습니다." description="필터를 바꾸거나 신규 심의를 요청하세요." />}
    </div>
  </div>
}
