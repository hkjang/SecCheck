import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, Bell, Check, CheckCheck, Settings2 } from 'lucide-react'
import { errorMessage, get, post, put } from '../lib/api'
import { Badge, Button, Empty, Field, Loading, Modal, Toggle, formatDate, useToast } from '../components/ui'

type Notice = { id: string; event_type: string; title: string; body: string; status: string; target_type: string; target_id: string; read_at?: string; created_at: string }
type Page = { items: Notice[]; total: number; has_more: boolean }
type EventInfo = { code: string; label: string; description: string }
type Preference = { email_enabled: boolean; digest: string; muted_events: string[] }
type PreferenceView = { preference: Preference; events: EventInfo[]; email_capable: boolean; email_address: string; digest_options: { code: string; label: string }[] }

export default function Notifications() {
  const toast = useToast()
  const [page, setPage] = useState<Page>()
  const [unreadOnly, setUnreadOnly] = useState(false)
  const [event, setEvent] = useState('')
  const [limit, setLimit] = useState(50)
  const [settings, setSettings] = useState<PreferenceView>()
  const [editing, setEditing] = useState(false)
  const params = useMemo(() => { const qs = new URLSearchParams({ limit: String(limit) }); if (unreadOnly) qs.set('unread', '1'); if (event) qs.set('event', event); return qs }, [unreadOnly, event, limit])
  const load = () => get<Page>(`/api/v1/notifications?${params}`).then(setPage)
  useEffect(() => { load().catch(e => toast.push(errorMessage(e), 'error')) }, [params])
  useEffect(() => { get<PreferenceView>('/api/v1/me/notification-preferences').then(setSettings).catch(() => undefined) }, [])

  const read = async (id: string) => { try { await post(`/api/v1/notifications/${id}/read`); load() } catch (e) { toast.push(errorMessage(e), 'error') } }
  const readAll = async () => { try { const out = await post<{ updated: number }>('/api/v1/notifications/read-all'); toast.push(`${out.updated}건을 읽음으로 표시했습니다.`); load() } catch (e) { toast.push(errorMessage(e), 'error') } }

  if (!page) return <Loading />
  const unread = page.items.filter(n => !n.read_at).length
  const labelOf = (code: string) => settings?.events.find(e => e.code === code)?.label || code
  return <div className="page">
    <div className="page-header"><div><h1 className="page-title">알림</h1><p className="page-description">제출, 배정, 보완, 승인 이벤트를 확인합니다. 전체 {page.total}건.</p></div>
      <div className="header-actions">{settings && <Button onClick={() => setEditing(true)}><Settings2 size={14} /> 수신 설정</Button>}{unread > 0 && <Button variant="primary" onClick={readAll}><CheckCheck size={14} /> 모두 읽음</Button>}</div></div>

    <div className="toolbar">
      <button type="button" className={`chip ${unreadOnly ? 'on' : ''}`} aria-pressed={unreadOnly} onClick={() => setUnreadOnly(!unreadOnly)}>읽지 않음만</button>
      <select className="select" aria-label="알림 유형" value={event} onChange={e => setEvent(e.target.value)}><option value="">전체 유형</option>{(settings?.events || []).map(e => <option key={e.code} value={e.code}>{e.label}</option>)}</select>
      {page.has_more && <Button small onClick={() => setLimit(limit + 50)}>더 보기</Button>}
    </div>

    <div className="card">{page.items.length ? <div>{page.items.map(n => <div className="card-body" key={n.id} data-sx="sx-001">
      <div className="stat-icon" data-sx="sx-055"><Bell size={16} /></div>
      <div data-sx="sx-016">
        <strong>{n.title}</strong> <Badge>{labelOf(n.event_type)}</Badge> {!n.read_at && <Badge tone="blue">새 알림</Badge>}
        <p className="subtle">{n.body}</p>
        <span className="subtle">{formatDate(n.created_at, true)}</span>
        {n.target_type === 'REVIEW_REQUEST' && n.target_id && <Link className="table-link" to={`/reviews/${n.target_id}`} onClick={() => { if (!n.read_at) read(n.id) }}> 심의 열기 <ArrowRight size={13} /></Link>}
      </div>
      {!n.read_at && <Button small onClick={() => read(n.id)}><Check size={13} /> 읽음</Button>}
    </div>)}</div> : <Empty title="조건에 맞는 알림이 없습니다." />}</div>

    {editing && settings && <PreferenceModal view={settings} onClose={() => setEditing(false)} onSaved={async () => { setEditing(false); setSettings(await get<PreferenceView>('/api/v1/me/notification-preferences')); toast.push('알림 수신 설정을 저장했습니다.') }} />}
  </div>
}

function PreferenceModal({ view, onClose, onSaved }: { view: PreferenceView; onClose: () => void; onSaved: () => Promise<void> }) {
  const toast = useToast()
  const [form, setForm] = useState<Preference>({ ...view.preference, muted_events: [...view.preference.muted_events] })
  const toggle = (code: string) => setForm(v => ({ ...v, muted_events: v.muted_events.includes(code) ? v.muted_events.filter(c => c !== code) : [...v.muted_events, code] }))
  const submit = async () => { try { await put('/api/v1/me/notification-preferences', form); await onSaved() } catch (e) { toast.push(errorMessage(e), 'error') } }
  return <Modal title="알림 수신 설정" onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant="primary" onClick={submit}>저장</Button></>}>
    {!view.email_capable && <div className="guide-block">이메일 알림이 서비스 전체에서 비활성화되어 있습니다. 아래 설정은 관리자가 이메일을 켜면 적용됩니다.</div>}
    {!view.email_address && <div className="guide-block">개인 프로필에 이메일 주소가 없어 메일을 받을 수 없습니다. 프로필에서 먼저 등록하세요.</div>}
    <div className="form-grid">
      <div className="span-2"><Toggle label="이메일로도 받기 (인앱 알림은 항상 기록됩니다)" value={form.email_enabled} onChange={v => setForm(f => ({ ...f, email_enabled: v }))} /></div>
      <Field label="수신 주기" help="요약을 선택하면 하루에 한 번 모아서 보냅니다."><select className="select" disabled={!form.email_enabled} value={form.digest} onChange={e => setForm(f => ({ ...f, digest: e.target.value }))}>{view.digest_options.map(o => <option key={o.code} value={o.code}>{o.label}</option>)}</select></Field>
    </div>
    <h4>이메일로 받지 않을 알림</h4>
    <p className="subtle">체크한 유형은 이메일로 보내지 않습니다. 알림 화면에는 그대로 남습니다.</p>
    <div className="grid two">{view.events.map(e => <label className="toggle-row" key={e.code}><span><strong>{e.label}</strong><div className="subtle">{e.description}</div></span><input type="checkbox" aria-label={`${e.label} 이메일 끄기`} disabled={!form.email_enabled} checked={form.muted_events.includes(e.code)} onChange={() => toggle(e.code)} /></label>)}</div>
  </Modal>
}
