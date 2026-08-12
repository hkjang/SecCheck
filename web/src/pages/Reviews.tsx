import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Filter, Plus, Search, ShieldCheck } from 'lucide-react'
import { get } from '../lib/api'
import { Review } from '../lib/types'
import { Button, Empty, Loading, StatusBadge, formatDate } from '../components/ui'

export default function Reviews({ security = false }: { security?: boolean }) {
  const [items, setItems] = useState<Review[]>()
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState(security ? 'SUBMITTED' : '')
  useEffect(() => { const timer = setTimeout(() => { const qs = new URLSearchParams(); if (query) qs.set('q', query); if (status) qs.set('status', status); get<Review[]>(`/api/v1/review-requests?${qs}`).then(setItems) }, 180); return () => clearTimeout(timer) }, [query, status])
  return <div className="page"><div className="page-header"><div><h1 className="page-title">{security ? '보안 검토 Queue' : '심의 목록'}</h1><p className="page-description">{security ? '제출·재제출된 건을 시작하고 항목별 검토를 진행하세요.' : '권한이 있는 심의 건만 표시됩니다.'}</p></div>{!security && <Link to="/reviews/new"><Button variant="primary"><Plus size={15} /> 신규 심의</Button></Link>}</div>
    <div className="card"><div className="card-body" data-sx="sx-045"><div className="toolbar"><div className="search-box"><Search /><input className="input" placeholder="심의번호, 서비스명, 부서 검색" value={query} onChange={e => setQuery(e.target.value)} /></div><Filter size={16} color="#6d7a8e" /><select className="select" data-sx="sx-051" value={status} onChange={e => setStatus(e.target.value)}><option value="">전체 상태</option><option value="DRAFT">작성 중</option><option value="SUBMITTED">제출 완료</option><option value="RESUBMITTED">재제출</option><option value="REVIEWING">검토 중</option><option value="CHANGE_REQUESTED">보완 요청</option><option value="APPROVAL_PENDING">승인 대기</option><option value="APPROVED">심의 완료</option><option value="REJECTED">반려</option></select></div></div>
      {!items ? <Loading /> : items.length ? <div className="table-wrap"><table><thead><tr><th>심의번호</th><th>서비스</th><th>유형</th><th>담당 부서</th><th>오픈 예정</th><th>상태</th><th></th></tr></thead><tbody>{items.map(item => <tr key={item.id}><td><Link className="table-link" to={`/reviews/${item.id}`}>{item.review_number}</Link></td><td><strong>{item.service_name}</strong></td><td>{item.service_type} · {item.change_type}</td><td>{item.department}</td><td>{formatDate(item.planned_open_date)}</td><td><StatusBadge status={item.status} /></td><td><Link to={`/reviews/${item.id}`}><Button small>{security ? <><ShieldCheck size={14} /> 검토</> : '상세'}</Button></Link></td></tr>)}</tbody></table></div> : <Empty title="조건에 맞는 심의가 없습니다." description="필터를 바꾸거나 신규 심의를 요청하세요." />}</div>
  </div>
}
