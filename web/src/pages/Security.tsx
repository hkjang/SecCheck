import { useEffect, useState } from 'react'
import { Copy, LogOut, MonitorSmartphone, ShieldCheck, ShieldOff, Smartphone } from 'lucide-react'
import { del, errorMessage, get, post } from '../lib/api'
import { AccountSecurity, SessionInfo } from '../lib/types'
import { Badge, Button, Empty, Field, Loading, Modal, formatDate, useToast } from '../components/ui'
import { useAuth } from '../main'

type Enrollment = { secret: string; raw_secret: string; uri: string; instructions: string }

export default function SecurityPage() {
  const { refresh } = useAuth()
  const toast = useToast()
  const [state, setState] = useState<AccountSecurity>()
  const [sessions, setSessions] = useState<SessionInfo[]>()
  const [enrollment, setEnrollment] = useState<Enrollment>()
  const [disabling, setDisabling] = useState(false)
  const load = () => Promise.all([get<AccountSecurity>('/api/v1/me/security'), get<SessionInfo[]>('/api/v1/me/sessions')]).then(([a, b]) => { setState(a); setSessions(b) })
  useEffect(() => { load().catch(e => toast.push(errorMessage(e), 'error')) }, [])

  const start = async () => { try { setEnrollment(await post<Enrollment>('/api/v1/me/totp/setup')) } catch (e) { toast.push(errorMessage(e), 'error') } }
  const revoke = async (id: string) => { try { await del(`/api/v1/me/sessions/${id}`); toast.push('세션을 종료했습니다.'); load() } catch (e) { toast.push(errorMessage(e), 'error') } }
  const revokeOthers = async () => { try { const out = await post<{ revoked: number }>('/api/v1/me/sessions/revoke-others'); toast.push(`${out.revoked}개 세션을 종료했습니다.`); load() } catch (e) { toast.push(errorMessage(e), 'error') } }

  if (!state || !sessions) return <Loading />
  const external = state.auth_source !== 'local'
  return <div className="page">
    <div className="page-header"><div><h1 className="page-title">계정 보안</h1><p className="page-description">일회용 코드와 로그인 세션을 직접 관리합니다.</p></div></div>
    {state.totp_required && !state.totp_enabled && <div className="card"><div className="card-body"><div className="guide-block"><strong>보안 정책에 따라 일회용 코드 등록이 필요합니다.</strong> 등록을 완료하기 전까지 다른 화면을 사용할 수 없습니다.</div></div></div>}

    <section className="card"><div className="card-header"><h2><Smartphone size={17} /> 일회용 코드 (TOTP)</h2>{state.totp_enabled ? <Badge tone="green">사용 중</Badge> : <Badge tone="amber">미설정</Badge>}</div>
      <div className="card-body">
        {external ? <p className="subtle">SSO 계정의 다중 인증은 사내 인증 서버에서 관리합니다.</p> : state.totp_enabled
          ? <><p className="subtle">{formatDate(state.totp_enrolled_at, true)}에 등록되었습니다. 로그인할 때마다 인증 앱의 6자리 코드가 필요합니다.</p><Button variant="danger" onClick={() => setDisabling(true)}><ShieldOff size={14} /> 해제</Button></>
          : <><p className="subtle">Google Authenticator, Microsoft Authenticator 등 표준 TOTP 앱을 사용합니다. 폐쇄망에서도 동작하며 서버는 외부 통신을 하지 않습니다.</p><Button variant="primary" onClick={start}><ShieldCheck size={14} /> 등록 시작</Button></>}
      </div></section>

    <section className="card"><div className="card-header"><h2><MonitorSmartphone size={17} /> 로그인 세션</h2><div className="header-actions"><Badge>{state.active_sessions}개</Badge>{sessions.length > 1 && <Button small onClick={revokeOthers}><LogOut size={13} /> 다른 세션 모두 종료</Button>}</div></div>
      {sessions.length ? <div className="table-wrap"><table><caption className="sr-only">현재 로그인된 세션</caption><thead><tr><th scope="col">접속 IP</th><th scope="col">브라우저</th><th scope="col">로그인</th><th scope="col">최근 활동</th><th scope="col"><span className="sr-only">작업</span></th></tr></thead>
        <tbody>{sessions.map(s => <tr key={s.id}><td>{s.source_ip || '-'}{s.current && <Badge tone="blue">현재 세션</Badge>}</td><td className="subtle" title={s.user_agent}>{shortAgent(s.user_agent)}</td><td>{formatDate(s.created_at, true)}</td><td>{formatDate(s.last_seen_at, true)}</td><td>{!s.current && <Button small variant="danger" onClick={() => revoke(s.id)}>종료</Button>}</td></tr>)}</tbody></table></div> : <Empty title="활성 세션이 없습니다." />}
    </section>

    {enrollment && <EnrollModal enrollment={enrollment} onClose={() => setEnrollment(undefined)} onDone={async () => { setEnrollment(undefined); await load(); await refresh(); toast.push('일회용 코드를 활성화했습니다. 다른 기기의 세션은 모두 종료되었습니다.') }} />}
    {disabling && <DisableModal onClose={() => setDisabling(false)} onDone={async () => { setDisabling(false); await load(); await refresh(); toast.push('일회용 코드를 해제했습니다.') }} />}
  </div>
}

function EnrollModal({ enrollment, onClose, onDone }: { enrollment: Enrollment; onClose: () => void; onDone: () => Promise<void> }) {
  const toast = useToast()
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = async () => { setBusy(true); try { await post('/api/v1/me/totp/enable', { code }); await onDone() } catch (e) { toast.push(errorMessage(e), 'error'); setCode('') } finally { setBusy(false) } }
  const copy = (value: string, label: string) => { navigator.clipboard.writeText(value); toast.push(`${label}을(를) 복사했습니다.`) }
  return <Modal title="일회용 코드 등록" onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant="primary" disabled={code.length < 6 || busy} onClick={submit}>활성화</Button></>}>
    <div className="guide-block">{enrollment.instructions}</div>
    <div className="form-grid">
      <Field label="비밀키" className="span-2" help="인증 앱의 '수동 입력' 또는 '설정 키 입력'에 붙여 넣으세요."><div data-sx="sx-013"><input className="input" readOnly value={enrollment.secret} /><Button onClick={() => copy(enrollment.raw_secret, '비밀키')}><Copy size={14} /> 복사</Button></div></Field>
      <Field label="otpauth URI" className="span-2" help="URI를 지원하는 앱은 이 값을 그대로 붙여 넣어도 됩니다."><div data-sx="sx-013"><input className="input" readOnly value={enrollment.uri} /><Button onClick={() => copy(enrollment.uri, 'URI')}><Copy size={14} /> 복사</Button></div></Field>
      <Field label="확인 코드" required help="앱에 표시된 6자리 숫자"><input className="input" inputMode="numeric" maxLength={6} placeholder="000000" value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ''))} /></Field>
    </div>
    <p className="subtle">기기를 분실하면 시스템 관리자가 사용자 및 역할 화면에서 초기화할 수 있습니다.</p>
  </Modal>
}

function DisableModal({ onClose, onDone }: { onClose: () => void; onDone: () => Promise<void> }) {
  const toast = useToast()
  const [password, setPassword] = useState('')
  const submit = async () => { try { await post('/api/v1/me/totp/disable', { current_password: password }); await onDone() } catch (e) { toast.push(errorMessage(e), 'error') } }
  return <Modal title="일회용 코드 해제" onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant="danger" disabled={!password} onClick={submit}>해제</Button></>}>
    <div className="guide-block">해제하면 비밀번호만으로 로그인할 수 있게 됩니다. 확인을 위해 현재 비밀번호를 입력하세요.</div>
    <Field label="현재 비밀번호" required><input type="password" className="input" autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} /></Field>
  </Modal>
}

// Full user-agent strings are unreadable in a table; the product and platform
// are enough to recognise your own device.
function shortAgent(agent: string) {
  if (!agent) return '알 수 없음'
  const browser = /Edg\/|Edge\//.test(agent) ? 'Edge' : /Chrome\//.test(agent) ? 'Chrome' : /Firefox\//.test(agent) ? 'Firefox' : /Safari\//.test(agent) ? 'Safari' : '기타 브라우저'
  const platform = /Windows/.test(agent) ? 'Windows' : /Macintosh|Mac OS/.test(agent) ? 'macOS' : /Android/.test(agent) ? 'Android' : /iPhone|iPad/.test(agent) ? 'iOS' : /Linux/.test(agent) ? 'Linux' : ''
  return platform ? `${browser} · ${platform}` : browser
}
