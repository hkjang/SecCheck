import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, ArrowRight, CalendarClock, CheckCircle2, ClipboardList, Clock3, Plus, ShieldCheck } from 'lucide-react'
import { get } from '../lib/api'
import { Review } from '../lib/types'
import { Badge, Button, Empty, Loading, StatusBadge, formatDate } from '../components/ui'
import { useAuth } from '../main'

type DashboardData = { status_counts: Record<string, number>; opening_soon: number; open_change_requests: number }
export default function Dashboard() {
  const { user } = useAuth()
  const [data, setData] = useState<DashboardData>()
  const [recent, setRecent] = useState<Review[]>([])
  useEffect(() => { Promise.all([get<DashboardData>('/api/v1/dashboard'), get<Review[]>('/api/v1/review-requests')]).then(([d, r]) => { setData(d); setRecent(r.slice(0, 7)) }) }, [])
  if (!data) return <Loading />
  const reviewMode = user.roles.some(r => ['SECURITY_REVIEWER', 'SYSTEM_ADMIN'].includes(r))
  const pending = (data.status_counts.SUBMITTED || 0) + (data.status_counts.RESUBMITTED || 0)
  const active = (data.status_counts.DRAFT || 0) + (data.status_counts.REVIEWING || 0)
  const completed = data.status_counts.APPROVED || 0
  return <div className="page"><div className="page-header"><div><h1 className="page-title">안녕하세요, {user.display_name}님</h1><p className="page-description">오늘 처리할 보안성 심의 업무를 확인하세요.</p></div><div className="header-actions">{user.roles.some(r => ['REQUESTER', 'SYSTEM_ADMIN'].includes(r)) && <Link to="/reviews/new"><Button variant="primary"><Plus size={15} /> 신규 심의 요청</Button></Link>}</div></div>
    <div className="grid stats"><div className="card stat-card"><div className="stat-icon"><ClipboardList /></div><div><span className="stat-value">{active}</span><div className="stat-label">진행 중 심의</div></div></div><div className="card stat-card"><div className="stat-icon amber"><AlertTriangle /></div><div><span className="stat-value">{reviewMode ? pending : data.open_change_requests}</span><div className="stat-label">{reviewMode ? '신규 검토 대기' : '미처리 보완 요청'}</div></div></div><div className="card stat-card"><div className="stat-icon red"><CalendarClock /></div><div><span className="stat-value">{data.opening_soon}</span><div className="stat-label">14일 내 오픈 예정</div></div></div><div className="card stat-card"><div className="stat-icon green"><ShieldCheck /></div><div><span className="stat-value">{completed}</span><div className="stat-label">심의 완료</div></div></div></div>
    <div className="grid two" style={{ marginTop: 18 }}><section className="card"><div className="card-header"><h2>최근 심의</h2><Link className="table-link" to="/reviews">전체 보기 <ArrowRight size={13} /></Link></div>{recent.length ? <div className="table-wrap"><table><thead><tr><th>심의번호 / 서비스</th><th>상태</th><th>오픈 예정</th></tr></thead><tbody>{recent.map(r => <tr key={r.id}><td><Link className="table-link" to={`/reviews/${r.id}`}>{r.review_number}</Link><div>{r.service_name}</div></td><td><StatusBadge status={r.status} /></td><td>{formatDate(r.planned_open_date)}</td></tr>)}</tbody></table></div> : <Empty title="최근 심의가 없습니다." />}</section>
      <section className="card"><div className="card-header"><h2>업무 흐름</h2><Badge tone="blue">Snapshot 기반</Badge></div><div className="card-body"><div style={{ display: 'grid', gap: 16 }}>{[['1', '서비스 정보 입력', 'Rule Engine이 적용할 체크리스트를 결정합니다.'], ['2', '체크리스트 작성·증적', '자동 저장과 서버 제출 검증으로 누락을 방지합니다.'], ['3', '검토·보완·재제출', '항목 단위 결과와 보완 이력이 계속 보존됩니다.'], ['4', '승인·결과 보존', '설정에 따라 승인 절차를 적용하고 이력을 고정합니다.']].map(([n, title, copy]) => <div key={n} style={{ display: 'flex', gap: 12 }}><div className="stat-icon" style={{ width: 34, height: 34, flex: 'none' }}>{n}</div><div><strong style={{ fontSize: 13 }}>{title}</strong><div className="subtle" style={{ marginTop: 3 }}>{copy}</div></div></div>)}</div></div></section></div>
  </div>
}
