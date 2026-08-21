import { useEffect, useState } from 'react'
import { AlertTriangle, RefreshCw, RotateCcw } from 'lucide-react'
import { errorMessage, get, post } from '../lib/api'
import { Badge, Button, Empty, Loading, formatDate, useToast } from '../components/ui'

type Job = { id: string; type: string; status: string; attempts: number; available_at: string; locked_at?: string; last_error: string; created_at: string; updated_at: string }
type Summary = { counts?: { type: string; status: string; count: number }[]; evidence_awaiting_scan: number; oldest_pending_seconds?: number }
const STALLED_AFTER = 300 // workers poll every 5s, so minutes of backlog means nothing is draining
const waited = (seconds: number) => seconds >= 3600 ? `${Math.floor(seconds / 3600)}시간 ${Math.floor(seconds % 3600 / 60)}분` : `${Math.max(1, Math.floor(seconds / 60))}분`
const typeLabel: Record<string, string> = { SEND_EMAIL: '이메일 알림', SCAN_EVIDENCE: '증적 악성코드 검사' }
const tone = (status: string) => status === 'FAILED' ? 'red' : status === 'RUNNING' ? 'blue' : status === 'PENDING' ? 'amber' : 'green'

export default function JobsPage() {
  const toast = useToast()
  const [data, setData] = useState<{ items: Job[]; summary: Summary }>()
  const [status, setStatus] = useState('')
  const [live, setLive] = useState(false)
  const load = () => { const qs = new URLSearchParams({ limit: '200' }); if (status) qs.set('status', status); return get<{ items: Job[]; summary: Summary }>(`/api/v1/admin/jobs?${qs}`).then(setData) }
  useEffect(() => {
    let alive = true
    const run = () => load().catch(() => undefined)
    run()
    const timer = live ? window.setInterval(() => { if (alive) run() }, 10000) : undefined
    return () => { alive = false; if (timer) clearInterval(timer) }
  }, [status, live])

  const retry = async (id: string) => { try { await post(`/api/v1/admin/jobs/${id}/retry`); toast.push('작업을 다시 큐에 넣었습니다.'); load() } catch (e) { toast.push(errorMessage(e), 'error') } }
  const retryAll = async () => { try { const out = await post<{ requeued: number }>('/api/v1/admin/jobs/retry-failed'); toast.push(`${out.requeued}건을 다시 큐에 넣었습니다.`); load() } catch (e) { toast.push(errorMessage(e), 'error') } }

  if (!data) return <Loading />
  const failed = (data.summary.counts || []).filter(c => c.status === 'FAILED').reduce((n, c) => n + Number(c.count), 0)
  const pending = (data.summary.counts || []).filter(c => c.status === 'PENDING').reduce((n, c) => n + Number(c.count), 0)
  const stalledFor = Number(data.summary.oldest_pending_seconds || 0)
  return <div className="page">
    <div className="page-header"><div><h1 className="page-title">작업 큐</h1><p className="page-description">이메일 알림과 증적 악성코드 검사는 백그라운드 큐에서 재시도됩니다. 실패한 작업을 여기서 확인하고 다시 실행합니다.</p></div>
      <div className="header-actions"><Button onClick={() => load()}><RefreshCw size={14} /> 새로고침</Button>{failed > 0 && <Button variant="primary" onClick={retryAll}><RotateCcw size={14} /> 실패 {failed}건 모두 재시도</Button>}</div></div>

    {stalledFor >= STALLED_AFTER && <div className="banner red" role="alert"><AlertTriangle size={16} /><div><strong>큐가 {waited(stalledFor)}째 처리되지 않고 있습니다.</strong> 실행 시각이 지난 작업이 남아 있어 알림 발송과 증적 검사가 멈춘 상태일 수 있습니다. 서버 로그에서 <code>notify</code>·<code>scanner</code> 구성요소의 오류를 확인하세요.</div></div>}

    <div className="grid stats">
      <div className="card stat-card"><div className="stat-icon amber"><RefreshCw /></div><div><span className="stat-value">{pending}</span><div className="stat-label">대기 중</div></div></div>
      <div className="card stat-card"><div className="stat-icon red"><AlertTriangle /></div><div><span className="stat-value">{failed}</span><div className="stat-label">실패</div></div></div>
      <div className="card stat-card"><div className="stat-icon"><RotateCcw /></div><div><span className="stat-value">{data.summary.evidence_awaiting_scan}</span><div className="stat-label">검사 대기 증적</div></div></div>
    </div>

    <div className="toolbar"><select className="select" aria-label="상태 필터" value={status} onChange={e => setStatus(e.target.value)}><option value="">전체 상태</option><option value="PENDING">대기</option><option value="RUNNING">실행 중</option><option value="FAILED">실패</option><option value="COMPLETED">완료</option></select>
      <button type="button" className={`chip ${live ? 'on' : ''}`} aria-pressed={live} onClick={() => setLive(!live)}>10초 자동 새로고침</button></div>

    <div className="card">{data.items.length ? <div className="table-wrap"><table><caption className="sr-only">백그라운드 작업 목록</caption>
      <thead><tr><th scope="col">유형</th><th scope="col">상태</th><th scope="col">시도</th><th scope="col">다음 실행</th><th scope="col">마지막 오류</th><th scope="col">변경</th><th scope="col"><span className="sr-only">작업</span></th></tr></thead>
      <tbody>{data.items.map(j => <tr key={j.id}><td>{typeLabel[j.type] || j.type}<div className="subtle"><code>{j.id.slice(0, 8)}</code></div></td><td><Badge tone={tone(j.status)}>{j.status}</Badge></td><td>{j.attempts}</td><td>{formatDate(j.available_at, true)}</td><td className="subtle" title={j.last_error}>{j.last_error ? j.last_error.slice(0, 90) : '-'}</td><td>{formatDate(j.updated_at, true)}</td><td>{j.status !== 'COMPLETED' && <Button small onClick={() => retry(j.id)}><RotateCcw size={13} /> 재시도</Button>}</td></tr>)}</tbody></table></div>
      : <Empty title="조건에 맞는 작업이 없습니다." description="큐가 비어 있으면 알림과 검사가 모두 정상 처리된 상태입니다." />}</div>
  </div>
}
