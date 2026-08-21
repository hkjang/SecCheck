import { useEffect, useMemo, useState } from 'react'
import { Download, RotateCcw, Search, ShieldCheck } from 'lucide-react'
import { errorMessage, get } from '../lib/api'
import { Badge, Button, Empty, Field, Loading, formatDate, useDownload, useToast } from '../components/ui'

const today = () => new Date().toISOString().slice(0, 10)

export default function AuditPage() {
  const toast = useToast()
  const save = useDownload()
  const [items, setItems] = useState<Record<string, unknown>[]>()
  const [events, setEvents] = useState<{ code: string; label: string }[]>([])
  const [filter, setFilter] = useState({ event: '', user: '', from: '', to: '', limit: '200' })
  const [detail, setDetail] = useState<Record<string, unknown>>()
  const params = useMemo(() => { const qs = new URLSearchParams(); Object.entries(filter).forEach(([k, v]) => { if (v) qs.set(k, v) }); return qs }, [filter])
  useEffect(() => { setItems(undefined); const timer = window.setTimeout(() => { get<{ items: Record<string, unknown>[]; events: { code: string; label: string }[] }>(`/api/v1/admin/audit?${params}`).then(page => { setItems(page.items); if (page.events?.length) setEvents(page.events) }) }, 200); return () => clearTimeout(timer) }, [params])
  const [verifying, setVerifying] = useState(false)
  // The routine check only proves what has been appended since the last run;
  // a full pass re-hashes the whole chain and is offered separately.
  const verify = async (full = false) => {
    setVerifying(true)
    try {
      const r = await get<{ valid: boolean; checked: number; total?: number; from_sequence: number; reason?: string }>(`/api/v1/admin/audit/verify${full ? '?full=1' : ''}`)
      if (!r.valid) { toast.push(`체인 불일치가 발견되었습니다 (${r.reason || '무결성 오류'}). 시스템 관리자에게 알림이 발송되었습니다.`, 'error'); return }
      toast.push(full
        ? `전체 ${r.checked}개 감사 이벤트의 해시 체인이 유효합니다.`
        : r.checked === 0 ? '이전 검증 이후 추가된 이벤트가 없습니다. 체인은 유효합니다.' : `신규 ${r.checked}개 이벤트를 검증했습니다. 누적 ${r.total ?? r.checked}개까지 체인이 유효합니다.`)
    } catch (e) { toast.push(errorMessage(e), 'error') } finally { setVerifying(false) }
  }
  const set = (key: keyof typeof filter, value: string) => setFilter(v => ({ ...v, [key]: value }))
  const active = Boolean(filter.event || filter.user || filter.from || filter.to)
  return <div className="page">
    <div className="page-header"><div><h1 className="page-title">감사로그</h1><p className="page-description">이전 이벤트 해시를 연결한 위변조 탐지 체인입니다. 애플리케이션에서 수정·삭제 API를 제공하지 않습니다.</p></div><div className="header-actions"><Button onClick={() => save(`/api/v1/admin/audit?${new URLSearchParams({ ...Object.fromEntries(params), format: 'csv' })}`)}><Download size={14} /> CSV 내보내기</Button><Button disabled={verifying} onClick={() => verify(false)}><ShieldCheck size={14} /> 체인 검증</Button><Button disabled={verifying} onClick={() => verify(true)}>전체 재검증</Button></div></div>
    <div className="card"><div className="card-body"><div className="form-grid">
      <Field label="이벤트 유형" help="앞부분만 입력해도 됩니다. 예: LOGIN"><div className="search-box"><Search /><input className="input" list="audit-events" placeholder="목록에서 고르거나 직접 입력" value={filter.event} onChange={e => set('event', e.target.value)} /><datalist id="audit-events">{events.map(e => <option key={e.code} value={e.code}>{e.label}</option>)}</datalist></div></Field>
      <Field label="사용자 / 접속 IP"><input className="input" placeholder="이름 또는 IP 일부" value={filter.user} onChange={e => set('user', e.target.value)} /></Field>
      <Field label="시작일"><input type="date" className="input" max={filter.to || today()} value={filter.from} onChange={e => set('from', e.target.value)} /></Field>
      <Field label="종료일"><input type="date" className="input" min={filter.from} max={today()} value={filter.to} onChange={e => set('to', e.target.value)} /></Field>
      <Field label="표시 건수"><select className="select" value={filter.limit} onChange={e => set('limit', e.target.value)}><option value="50">50</option><option value="200">200</option></select></Field>
      <div className="field"><label>&nbsp;</label><Button disabled={!active} onClick={() => setFilter({ event: '', user: '', from: '', to: '', limit: filter.limit })}><RotateCcw size={13} /> 필터 초기화</Button></div>
    </div></div>
      {!items ? <Loading /> : items.length ? <div className="table-wrap"><table><thead><tr><th>시각</th><th>이벤트</th><th>사용자 / IP</th><th>대상</th><th>결과</th><th>해시</th></tr></thead><tbody>{items.map(x => <tr key={String(x.event_id)}><td>{formatDate(x.timestamp, true)}</td><td><button className="link-button" onClick={() => setDetail(x)}><Badge tone="blue">{String(x.event_label || x.event_type)}</Badge></button><div className="subtle">{String(x.event_type)}</div></td><td>{String(x.user_name || '-')}<div className="subtle">{String(x.source_ip || '')}</div></td><td>{String(x.target_type)}<div className="subtle">{String(x.target_id)}</div></td><td><Badge tone={x.result === 'SUCCESS' ? 'green' : 'red'}>{String(x.result)}</Badge></td><td><code title={String(x.event_hash)}>{String(x.event_hash).slice(0, 12)}…</code></td></tr>)}</tbody></table></div> : <Empty title="조건에 맞는 감사 이벤트가 없습니다." description="필터를 넓히거나 기간을 조정하세요." />}
    </div>
    {detail && <AuditDetail event={detail} onClose={() => setDetail(undefined)} />}
  </div>
}

function AuditDetail({ event, onClose }: { event: Record<string, unknown>; onClose: () => void }) {
  const rows: [string, string][] = [['이벤트', `${event.event_label || ''} (${event.event_type})`.trim()], ['시각', formatDate(event.timestamp, true)], ['사용자', String(event.user_name || '-')], ['접속 IP', String(event.source_ip || '-')], ['대상', `${event.target_type} ${event.target_id || ''}`.trim()], ['결과', String(event.result)], ['요청 ID', String(event.request_id || '-')], ['이전 해시', String(event.previous_hash || '-')], ['이벤트 해시', String(event.event_hash || '-')]]
  return <div className="modal-backdrop" onMouseDown={e => e.target === e.currentTarget && onClose()}><div className="modal"><div className="modal-header"><strong>감사 이벤트 상세</strong><Button variant="ghost" onClick={onClose}>닫기</Button></div><div className="modal-body">
    <div className="table-wrap"><table><tbody>{rows.map(([label, value]) => <tr key={label}><th>{label}</th><td style={{ wordBreak: 'break-all' }}>{value}</td></tr>)}</tbody></table></div>
    {Boolean(event.before_value) && <><h4>변경 전</h4><div className="guide-block"><code>{JSON.stringify(event.before_value, null, 2)}</code></div></>}
    {Boolean(event.after_value) && <><h4>변경 후</h4><div className="guide-block"><code>{JSON.stringify(event.after_value, null, 2)}</code></div></>}
  </div></div></div>
}
