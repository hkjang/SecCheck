import { useEffect, useState } from 'react'
import { RefreshCw, Search } from 'lucide-react'
import { get } from '../lib/api'
import { Badge, Button, Empty, LoadFailed, Loading, Toggle, formatDate } from '../components/ui'

export default function LogsPage() {
  const [items, setItems] = useState<Record<string, unknown>[]>()
  const [level, setLevel] = useState('')
  const [query, setQuery] = useState('')
  const [live, setLive] = useState(false)
  // The tail is capped, and a capped list that says nothing reads as "this is
  // everything that happened".
  const [truncated, setTruncated] = useState(false)
  const [failed, setFailed] = useState<unknown>()
  useEffect(() => {
    let alive = true
    const load = () => { const qs = new URLSearchParams({ limit: '200' }); if (level) qs.set('level', level); if (query.trim()) qs.set('q', query.trim()); return get<{ items: Record<string, unknown>[]; has_more: boolean }>(`/api/v1/admin/logs?${qs}`).then(v => { if (alive) { setItems(v.items); setTruncated(Boolean(v.has_more)) } }).catch(err => { if (alive) setFailed(err) }) }
    const timer = window.setTimeout(load, 200)
    const interval = live ? window.setInterval(load, 10000) : undefined
    return () => { alive = false; clearTimeout(timer); if (interval) clearInterval(interval) }
  }, [level, query, live])
  return <div className="page"><div className="page-header"><div><h1 className="page-title">서버 로그</h1><p className="page-description">민감정보를 제외한 구조화된 운영 로그와 요청 ID를 확인합니다. 검색은 메시지, 구성요소, 요청 ID와 필드를 함께 조회합니다.</p></div><Button onClick={() => setQuery(q => q)}><RefreshCw size={14} /> 새로고침</Button></div>
    <div className="toolbar"><div className="search-box"><Search /><input className="input" placeholder="메시지, 구성요소, 요청 ID, 경로 검색" value={query} onChange={e => setQuery(e.target.value)} /></div><select className="select" data-sx="sx-050" value={level} onChange={e => setLevel(e.target.value)}><option value="">전체 레벨</option><option>ERROR</option><option>WARN</option><option>INFO</option></select><div style={{ minWidth: 210 }}><Toggle label="10초 자동 새로고침" value={live} onChange={setLive} /></div></div>
    {truncated && <div className="card"><div className="card-body"><p className="subtle">최근 200건만 표시합니다. 더 오래된 로그는 레벨·검색어로 조건을 좁혀 확인하세요.</p></div></div>}
    <div className="card">{failed ? <LoadFailed error={failed} /> : !items ? <Loading /> : items.length ? <div className="table-wrap"><table><thead><tr><th>시각</th><th>레벨</th><th>구성요소</th><th>메시지</th><th>요청 ID</th></tr></thead><tbody>{items.map(x => <tr key={String(x.id)}><td>{formatDate(x.timestamp, true)}</td><td><Badge tone={x.level === 'ERROR' ? 'red' : x.level === 'WARN' ? 'amber' : 'blue'}>{String(x.level)}</Badge></td><td>{String(x.component)}</td><td>{String(x.message)}<div className="subtle">{JSON.stringify(x.fields)}</div></td><td><code>{String(x.request_id || '-')}</code></td></tr>)}</tbody></table></div> : <Empty title="조건에 맞는 서버 로그가 없습니다." />}</div></div>
}
