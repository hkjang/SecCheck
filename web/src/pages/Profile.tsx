import { FormEvent, useState } from 'react'
import { KeyRound, Save, UserCircle2 } from 'lucide-react'
import { patch, put, errorMessage } from '../lib/api'
import { Button, Field, useToast } from '../components/ui'
import { useAuth } from '../main'

export default function ProfilePage() { const { user, refresh, passwordChangeRequired } = useAuth(); const toast = useToast(); const [form, setForm] = useState({ display_name: user.display_name, email: user.email, department: user.department }); const submit = async (e: FormEvent) => { e.preventDefault(); try { await patch('/api/v1/me', form); await refresh(); toast.push('프로필을 저장했습니다.') } catch (e) { toast.push(errorMessage(e), 'error') } }; return <div className="page"><div className="page-header"><div><h1 className="page-title">개인 프로필</h1><p className="page-description">개인화 설정은 서비스 관리자 설정과 분리되어 있습니다.</p></div></div>{passwordChangeRequired && <div className="card"><div className="card-body"><strong>임시 비밀번호로 로그인했습니다.</strong><p className="subtle">관리자가 발급한 비밀번호는 발급한 사람도 알고 있는 값입니다. 아래에서 본인만 아는 비밀번호로 바꾸어야 나머지 화면을 사용할 수 있습니다.</p></div></div>}<form className="card" onSubmit={submit} data-sx="sx-040"><div className="card-header"><h2><UserCircle2 size={17} /> 기본정보</h2></div><div className="card-body"><div className="form-grid"><Field label="사용자명"><input className="input" disabled value={user.username} /></Field><Field label="인증 원본"><input className="input" disabled value={user.auth_source.toUpperCase()} /></Field><Field label="표시 이름"><input className="input" value={form.display_name} onChange={e => setForm(v => ({ ...v, display_name: e.target.value }))} /></Field><Field label="이메일"><input className="input" value={form.email} onChange={e => setForm(v => ({ ...v, email: e.target.value }))} /></Field><Field label="부서"><input className="input" value={form.department} onChange={e => setForm(v => ({ ...v, department: e.target.value }))} /></Field><Field label="역할"><div>{user.roles.map(r => <span className="badge purple" key={r}>{r}</span>)}</div></Field></div><div data-sx="sx-048"><Button variant="primary"><Save size={14} /> 저장</Button></div></div></form>{user.auth_source === 'local' && <PasswordCard />}</div> }

function PasswordCard() {
  const toast = useToast()
  const { refresh } = useAuth()
  const [form, setForm] = useState({ current_password: '', new_password: '', confirm: '' })
  const [busy, setBusy] = useState(false)
  const mismatch = Boolean(form.confirm) && form.new_password !== form.confirm
  const tooShort = Boolean(form.new_password) && form.new_password.length < 12
  const ready = form.current_password && form.new_password.length >= 12 && form.new_password === form.confirm
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try { await put('/api/v1/me/password', { current_password: form.current_password, new_password: form.new_password }); setForm({ current_password: '', new_password: '', confirm: '' }); toast.push('비밀번호를 변경했습니다. 다른 기기의 로그인 세션은 모두 종료되었습니다.'); await refresh() }
    catch (e) { toast.push(errorMessage(e), 'error') }
    finally { setBusy(false) }
  }
  return <form className="card" onSubmit={submit} data-sx="sx-040"><div className="card-header"><h2><KeyRound size={17} /> 비밀번호 변경</h2></div><div className="card-body"><div className="form-grid"><Field label="현재 비밀번호" required className="span-2"><input type="password" className="input" autoComplete="current-password" value={form.current_password} onChange={e => setForm(v => ({ ...v, current_password: e.target.value }))} /></Field><Field label="새 비밀번호" required help="12자 이상" error={tooShort ? '12자 이상이어야 합니다.' : ''}><input type="password" className="input" autoComplete="new-password" value={form.new_password} onChange={e => setForm(v => ({ ...v, new_password: e.target.value }))} /></Field><Field label="새 비밀번호 확인" required error={mismatch ? '새 비밀번호가 일치하지 않습니다.' : ''}><input type="password" className="input" autoComplete="new-password" value={form.confirm} onChange={e => setForm(v => ({ ...v, confirm: e.target.value }))} /></Field></div><div className="guide-block">변경하면 현재 사용 중인 브라우저를 제외한 모든 로그인 세션이 즉시 종료되고, 로그인 실패 잠금 카운터도 초기화됩니다.</div><div data-sx="sx-048"><Button variant="primary" disabled={!ready || busy}><Save size={14} /> 비밀번호 변경</Button></div></div></form>
}
