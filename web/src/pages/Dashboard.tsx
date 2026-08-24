import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, ArrowRight, CalendarClock, ClipboardCheck, ClipboardList, Hourglass, Inbox, Plus, ShieldCheck } from 'lucide-react'
import { get } from '../lib/api'
import { DueChange, Page, QueueEntry, Review } from '../lib/types'
import { Badge, Button, Empty, formatDate, LoadFailed, Loading, StatusBadge } from '../components/ui'
import { useAuth } from '../main'

type FollowUp = { id: string; review_id: string; review_number: string; service_name: string; item_code: string; title: string; follow_up: string; due_date?: string; overdue: boolean; reported: boolean }
type DashboardData = { status_counts: Record<string, number>; opening_soon: number; opening_soon_unfinished: number; open_change_requests: number; my_queue: QueueEntry[]; due_soon: DueChange[]; my_follow_ups?: FollowUp[]; security_analytics?: { unassigned?: number; long_pending?: number; long_pending_days?: number } }
export default function Dashboard() {
  const { user } = useAuth()
  // Only a security lead sees these; for everybody else the server omits them.
  const [data, setData] = useState<DashboardData>()
  const [recent, setRecent] = useState<Review[]>([])
  const [failed, setFailed] = useState<unknown>()
  const load = () => { setFailed(undefined); Promise.all([get<DashboardData>('/api/v1/dashboard'), get<Page<Review>>('/api/v1/review-requests?limit=7')]).then(([d, r]) => { setData(d); setRecent(r.items) }).catch(setFailed) }
  useEffect(load, [])
  if (failed) return <LoadFailed error={failed} onRetry={load} />
  if (!data) return <Loading />
  const reviewMode = user.roles.some(r => ['SECURITY_REVIEWER', 'SYSTEM_ADMIN'].includes(r))
  const pending = (data.status_counts.SUBMITTED || 0) + (data.status_counts.RESUBMITTED || 0)
  const active = (data.status_counts.DRAFT || 0) + (data.status_counts.REVIEWING || 0)
  const completed = data.status_counts.APPROVED || 0
  const queue = data.my_queue || []
  const due = data.due_soon || []
  const actions = data.my_follow_ups || []
  const analytics = data.security_analytics
  return <div className="page"><div className="page-header"><div><h1 className="page-title">안녕하세요, {user.display_name}님</h1><p className="page-description">오늘 처리할 보안성 심의 업무를 확인하세요.</p></div><div className="header-actions">{user.roles.some(r => ['REQUESTER', 'SYSTEM_ADMIN'].includes(r)) && <Link to="/reviews/new"><Button variant="primary"><Plus size={15} /> 신규 심의 요청</Button></Link>}</div></div>
    {/* Every number here is a set of reviews, so every number opens that set:
        reading a count and then rebuilding the filter by hand was the whole
        distance between the landing page and the work. */}
    <div className="grid stats"><Link className="card stat-card" to="/reviews?status=DRAFT,REVIEWING"><div className="stat-icon"><ClipboardList /></div><div><span className="stat-value">{active}</span><div className="stat-label">진행 중 심의</div></div></Link><Link className="card stat-card" to={reviewMode ? '/reviews?status=SUBMITTED,RESUBMITTED' : '/reviews?open_changes=1'}><div className="stat-icon amber"><AlertTriangle /></div><div><span className="stat-value">{reviewMode ? pending : data.open_change_requests}</span><div className="stat-label">{reviewMode ? '신규 검토 대기' : '미처리 보완 요청'}</div></div></Link><Link className="card stat-card" to="/reviews?open_at_risk=1"><div className="stat-icon red"><CalendarClock /></div><div><span className="stat-value">{data.opening_soon}</span><div className="stat-label">14일 내 오픈 예정{data.opening_soon_unfinished > 0 && <> · <strong data-sx="sx-060">미완료 {data.opening_soon_unfinished}건</strong></>}</div></div></Link><Link className="card stat-card" to="/reviews?status=APPROVED"><div className="stat-icon green"><ShieldCheck /></div><div><span className="stat-value">{completed}</span><div className="stat-label">심의 완료</div></div></Link></div>

    {analytics && (Number(analytics.unassigned) > 0 || Number(analytics.long_pending) > 0) && <section className="card"><div className="card-header"><h2><Hourglass size={17} /> 대기열 상태</h2></div><div className="card-body" data-sx="sx-006">
      {/* Both numbers are counted the same way the reminder mails count them,
          and each links to the list that holds exactly those reviews. */}
      <Link className="table-link" to="/reviews?unassigned=1">담당자 없는 심의 {analytics.unassigned ?? 0}건 <ArrowRight size={13} /></Link>
      <Link className="table-link" to="/reviews?stalled=1">{analytics.long_pending_days ?? 3}일 이상 멈춘 심의 {analytics.long_pending ?? 0}건 <ArrowRight size={13} /></Link>
    </div></section>}

    <section className="card"><div className="card-header"><h2><Inbox size={17} /> 내 차례</h2><div className="header-actions"><Badge tone={queue.length ? 'blue' : ''}>{queue.length}건</Badge><Link className="table-link" to="/reviews?mine=1">전체 보기 <ArrowRight size={13} /></Link></div></div>
      <div className="card-body">{queue.length ? queue.map(q => <div className="queue-row" key={q.id}><Badge tone="blue">{q.action}</Badge><div className="grow"><Link className="table-link" to={`/reviews/${q.id}`}>{q.review_number}</Link> <strong>{q.service_name}</strong><span className="subtle">오픈 예정 {formatDate(q.planned_open_date)} · 최근 변경 {formatDate(q.updated_at, true)}</span></div><StatusBadge status={q.status} /></div>) : <Empty title="지금 처리할 심의가 없습니다." description="새로 배정되면 상단 알림과 이 목록에 함께 표시됩니다." />}</div></section>

    {due.length > 0 && <section className="card"><div className="card-header"><h2><CalendarClock size={17} /> 보완 조치 기한</h2><Badge tone={due.some(d => d.overdue) ? 'red' : 'amber'}>{due.length}건</Badge></div>
      <div className="table-wrap"><table><caption className="sr-only">기한이 임박했거나 지난 보완 요청</caption><thead><tr><th scope="col">심의</th><th scope="col">항목</th><th scope="col">기한</th><th scope="col">상태</th></tr></thead><tbody>{due.map(d => <tr key={d.id}><td><Link className="table-link" to={`/reviews/${d.review_request_id}`}>{d.review_number}</Link><div className="subtle">{d.service_name}</div></td><td><strong>{d.item_code}</strong><div className="subtle">{d.title}</div></td><td>{formatDate(d.due_date)}</td><td><Badge tone={d.overdue ? 'red' : 'amber'}>{d.overdue ? '기한 초과' : '임박'}</Badge></td></tr>)}</tbody></table></div></section>}

    {actions.length > 0 && <section className="card">
      <div className="card-header"><h2><ClipboardCheck size={17} /> 내 후속조치</h2><Badge tone={actions.some(a => a.overdue) ? 'red' : 'amber'}>{actions.length}건</Badge></div>
      <div className="table-wrap"><table><caption className="sr-only">이행해야 할 후속조치</caption>
        <thead><tr><th scope="col">심의</th><th scope="col">항목</th><th scope="col">조치 사항</th><th scope="col">기한</th><th scope="col">상태</th></tr></thead>
        <tbody>{actions.map(a => <tr key={a.id}>
          <td><Link className="table-link" to={`/reviews/${a.review_id}`}>{a.review_number}</Link><div className="subtle">{a.service_name}</div></td>
          <td><strong>{a.item_code}</strong><div className="subtle">{a.title}</div></td>
          <td>{a.follow_up}</td>
          <td>{a.due_date ? formatDate(a.due_date) : <span className="subtle">기한 없음</span>}</td>
          <td>{a.reported ? <Badge tone="blue">확인 대기</Badge> : a.overdue ? <Badge tone="red">기한 초과</Badge> : <Badge tone="amber">미조치</Badge>}</td>
        </tr>)}</tbody></table></div>
    </section>}

    <div className="grid two" data-sx="sx-031"><section className="card"><div className="card-header"><h2>최근 심의</h2><Link className="table-link" to="/reviews">전체 보기 <ArrowRight size={13} /></Link></div>{recent.length ? <div className="table-wrap"><table><caption className="sr-only">최근 심의</caption><thead><tr><th scope="col">심의번호 / 서비스</th><th scope="col">상태</th><th scope="col">오픈 예정</th></tr></thead><tbody>{recent.map(r => <tr key={r.id}><td><Link className="table-link" to={`/reviews/${r.id}`}>{r.review_number}</Link><div>{r.service_name}</div></td><td><StatusBadge status={r.status} /></td><td>{formatDate(r.planned_open_date)}</td></tr>)}</tbody></table></div> : <Empty title="최근 심의가 없습니다." />}</section>
      <section className="card"><div className="card-header"><h2>업무 흐름</h2><Badge tone="blue">Snapshot 기반</Badge></div><div className="card-body"><div data-sx="sx-014">{[['1', '서비스 정보 입력', 'Rule Engine이 적용할 체크리스트를 결정합니다.'], ['2', '체크리스트 작성·증적', '자동 저장과 서버 제출 검증으로 누락을 방지합니다.'], ['3', '검토·보완·재제출', '항목 단위 결과와 보완 이력이 계속 보존됩니다.'], ['4', '승인·결과 보존', '설정에 따라 승인 절차를 적용하고 이력을 고정합니다.']].map(([n, title, copy]) => <div key={n} data-sx="sx-005"><div className="stat-icon" data-sx="sx-054">{n}</div><div><strong data-sx="sx-018">{title}</strong><div className="subtle" data-sx="sx-033">{copy}</div></div></div>)}</div></div></section></div>
  </div>
}
