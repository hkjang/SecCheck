import { useEffect, useMemo, useState } from 'react'
import { KeyRound, LockOpen, Plus, Search, Shield, Smartphone, UserCheck, UserX } from 'lucide-react'
import { errorMessage, forgetDirectory, get, post, put } from '../lib/api'
import { User } from '../lib/types'
import { Badge, Button, Empty, Field, Loading, Modal, formatDate, useToast } from '../components/ui'

const roleNames: Record<string, string> = { SYSTEM_ADMIN: '시스템 관리자', TEMPLATE_ADMIN: '체크리스트 관리자', SECURITY_REVIEWER: '보안 담당자', REQUESTER: '심의 요청자', CONTRIBUTOR: '공동 작성자', APPROVER: '승인자', AUDITOR: '감사자' }
// The service locks a privileged account that has not signed in for
// inactive_admin_lock_days, and an access review asks the same question of
// everyone else. Neither was answerable from this page.
const privileged = ['SYSTEM_ADMIN', 'TEMPLATE_ADMIN', 'SECURITY_REVIEWER', 'APPROVER']
const daysSince = (at?: string | null) => at ? Math.floor((Date.now() - new Date(at).getTime()) / 86400000) : null

export default function UsersPage() {
  const toast = useToast(); const [users, setUsers] = useState<User[]>(); const [create, setCreate] = useState(false); const [edit, setEdit] = useState<User>(); const [reset, setReset] = useState<User>(); const [query, setQuery] = useState(''); const [only, setOnly] = useState(''); const load = () => get<User[]>('/api/v1/admin/users').then(setUsers); useEffect(() => { load() }, [])
  const [lockDays, setLockDays] = useState(90)
  useEffect(() => { get<{ key: string; value: Record<string, unknown> }[]>('/api/v1/admin/settings').then(all => {
    const security = all.find(x => x.key === 'security')
    const days = Number(security?.value?.inactive_admin_lock_days)
    if (days > 0) setLockDays(days)
  }).catch(() => undefined) }, [])
  const stale = (u: User) => { const days = daysSince(u.last_login_at); return days !== null && days >= lockDays }
  const shown = useMemo(() => (users || []).filter(u => {
    const term = query.trim().toLowerCase()
    if (term && ![u.display_name, u.username, u.email, u.department, ...u.roles].some(v => (v || '').toLowerCase().includes(term))) return false
    if (only === 'LOCKED') return Boolean(u.locked_until)
    if (only === 'INACTIVE') return !u.active
    if (only === 'OIDC') return u.auth_source === 'oidc'
    if (only === 'LOCAL') return u.auth_source === 'local'
    if (only === 'STALE') return u.active && (stale(u) || !u.last_login_at)
    return true
  }), [users, query, only, lockDays])
  const lockedCount = (users || []).filter(u => u.locked_until).length
  const active = async (user: User) => { try { await post(`/api/v1/admin/users/${user.id}/active`, { active: !user.active }); forgetDirectory(); toast.push(user.active ? '계정을 비활성화했습니다.' : '계정을 활성화했습니다.'); load() } catch (e) { toast.push(errorMessage(e), 'error') } }
  const unlock = async (user: User) => { try { await post(`/api/v1/admin/users/${user.id}/unlock`); toast.push('로그인 잠금을 해제했습니다.'); load() } catch (e) { toast.push(errorMessage(e), 'error') } }
  const resetTotp = async (user: User) => { if (!confirm(`${user.display_name} 계정의 일회용 코드를 초기화할까요? 해당 사용자의 모든 세션이 종료됩니다.`)) return; try { await post(`/api/v1/admin/users/${user.id}/totp/reset`); toast.push('일회용 코드를 초기화했습니다.'); load() } catch (e) { toast.push(errorMessage(e), 'error') } }
  return <div className="page"><div className="page-header"><div><h1 className="page-title">사용자 및 역할</h1><p className="page-description">RBAC 역할을 조합하고 비활성 계정의 세션을 즉시 종료하며, 로그인 실패로 잠긴 계정을 해제하거나 임시 비밀번호를 발급합니다.</p></div><Button variant="primary" onClick={() => setCreate(true)}><Plus size={15} /> 로컬 사용자</Button></div>
    <div className="toolbar"><div className="search-box"><Search /><input className="input" placeholder="이름, 아이디, 이메일, 부서, 역할 검색" value={query} onChange={e => setQuery(e.target.value)} /></div><select className="select" value={only} onChange={e => setOnly(e.target.value)}><option value="">전체 계정</option><option value="LOCKED">로그인 잠김{lockedCount ? ` (${lockedCount})` : ''}</option><option value="INACTIVE">비활성</option><option value="LOCAL">로컬 계정</option><option value="OIDC">SSO 계정</option><option value="STALE">{lockDays}일 이상 미접속</option></select><span className="subtle">{shown.length} / {(users || []).length}명</span></div>
    <div className="card">{!users ? <Loading /> : shown.length ? <div className="table-wrap"><table><thead><tr><th>사용자</th><th>부서</th><th>인증</th><th>역할</th><th>마지막 접속</th><th>상태</th><th></th></tr></thead><tbody>{shown.map(u => <tr key={u.id}><td><strong>{u.display_name}</strong><div className="subtle">{u.username} · {u.email}</div></td><td>{u.department || '-'}</td><td><Badge tone={u.auth_source === 'oidc' ? 'blue' : ''}>{u.auth_source.toUpperCase()}</Badge></td><td>{u.roles.map(r => <Badge key={r} tone={r === 'SYSTEM_ADMIN' ? 'red' : 'purple'}>{roleNames[r] || r}</Badge>)}</td><td><LastSeen user={u} lockDays={lockDays} /></td><td><Badge tone={u.active ? 'green' : 'red'}>{u.active ? '활성' : '비활성'}</Badge>{u.totp_enabled && <Badge tone="purple">MFA</Badge>}{u.locked_until && <><Badge tone="red">로그인 잠김</Badge><div className="subtle">{formatDate(u.locked_until, true)}까지</div></>}</td><td><div data-sx="sx-007"><Button small onClick={() => setEdit(u)}><Shield size={13} /> 역할</Button>{u.locked_until && <Button small onClick={() => unlock(u)}><LockOpen size={13} /> 잠금 해제</Button>}{u.auth_source === 'local' && <Button small onClick={() => setReset(u)}><KeyRound size={13} /> 비밀번호</Button>}{u.auth_source === 'local' && u.totp_enabled && <Button small onClick={() => resetTotp(u)}><Smartphone size={13} /> 코드 초기화</Button>}<Button small variant={u.active ? 'danger' : ''} onClick={() => active(u)}>{u.active ? <UserX size={13} /> : <UserCheck size={13} />}</Button></div></td></tr>)}</tbody></table></div> : <Empty title="조건에 맞는 사용자가 없습니다." />}</div>{create && <CreateUser onClose={() => setCreate(false)} onSaved={load} />}{edit && <RoleModal user={edit} onClose={() => setEdit(undefined)} onSaved={load} />}{reset && <ResetPasswordModal user={reset} onClose={() => setReset(undefined)} onSaved={load} />}</div>
}

function ResetPasswordModal({ user, onClose, onSaved }: { user: User; onClose: () => void; onSaved: () => void }) {
  const toast = useToast()
  const [password, setPassword] = useState('')
  const generate = () => { const bytes = new Uint8Array(18); crypto.getRandomValues(bytes); setPassword(btoa(String.fromCharCode(...bytes)).replace(/[+/=]/g, 'x').slice(0, 20)) }
  const submit = async () => {
    try { await post(`/api/v1/admin/users/${user.id}/password`, { password }); toast.push(`${user.display_name} 계정의 임시 비밀번호를 설정했습니다.`); onClose(); onSaved() }
    catch (e) { toast.push(errorMessage(e), 'error') }
  }
  return <Modal title={`${user.display_name} 비밀번호 재설정`} onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant="primary" disabled={password.length < 12} onClick={submit}>재설정</Button></>}>
    <div className="guide-block">임시 비밀번호를 안전한 경로로 본인에게 전달하고, 첫 로그인 후 개인 프로필에서 변경하도록 안내하세요. 재설정 즉시 이 계정의 모든 로그인 세션이 종료되고 잠금이 해제됩니다.</div>
    <div className="form-grid"><Field label="임시 비밀번호" required className="span-2" help="12자 이상"><input className="input" value={password} onChange={e => setPassword(e.target.value)} /></Field><div className="span-2"><Button onClick={generate}><KeyRound size={13} /> 임의 생성</Button>{password && <Button onClick={() => { navigator.clipboard.writeText(password); toast.push('클립보드에 복사했습니다.') }}>복사</Button>}</div></div>
  </Modal>
}
function CreateUser({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) { const toast = useToast(); const [form, setForm] = useState({ username: '', display_name: '', email: '', department: '', password: '', roles: ['REQUESTER'] }); const submit = async () => { try { await post('/api/v1/admin/users', form); forgetDirectory(); toast.push('로컬 사용자를 만들었습니다.'); onClose(); onSaved() } catch (e) { toast.push(errorMessage(e), 'error') } }; return <Modal title="로컬 사용자 생성" onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant="primary" onClick={submit}>생성</Button></>}><div className="form-grid"><Field label="사용자명" required><input className="input" value={form.username} onChange={e => setForm(v => ({ ...v, username: e.target.value }))} /></Field><Field label="표시 이름" required><input className="input" value={form.display_name} onChange={e => setForm(v => ({ ...v, display_name: e.target.value }))} /></Field><Field label="이메일"><input className="input" value={form.email} onChange={e => setForm(v => ({ ...v, email: e.target.value }))} /></Field><Field label="부서"><input className="input" value={form.department} onChange={e => setForm(v => ({ ...v, department: e.target.value }))} /></Field><Field label="초기 비밀번호" required help="12자 이상"><input type="password" className="input" value={form.password} onChange={e => setForm(v => ({ ...v, password: e.target.value }))} /></Field><div className="span-2"><RoleChecks value={form.roles} onChange={roles => setForm(v => ({ ...v, roles }))} /></div></div></Modal> }
function RoleModal({ user, onClose, onSaved }: { user: User; onClose: () => void; onSaved: () => void }) { const toast = useToast(); const [roles, setRoles] = useState(user.roles); const save = async () => { try { await put(`/api/v1/admin/users/${user.id}/roles`, { roles }); toast.push('역할을 저장했습니다.'); onClose(); onSaved() } catch (e) { toast.push(errorMessage(e), 'error') } }; return <Modal title={`${user.display_name} 역할`} onClose={onClose} footer={<><Button onClick={onClose}>취소</Button><Button variant="primary" onClick={save}>저장</Button></>}><RoleChecks value={roles} onChange={setRoles} /></Modal> }
function RoleChecks({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) { return <div className="grid two">{Object.entries(roleNames).map(([code, name]) => <label className="toggle-row" key={code}><span><strong>{name}</strong><div className="subtle">{code}</div></span><input type="checkbox" checked={value.includes(code)} onChange={e => onChange(e.target.checked ? [...value, code] : value.filter(v => v !== code))} /></label>)}</div> }

// A privileged account is locked after lockDays without a sign-in, so the
// warning is only meaningful for those roles; for everyone else the age is
// still what an access review needs to see.
function LastSeen({ user, lockDays }: { user: User; lockDays: number }) {
  const days = daysSince(user.last_login_at)
  if (days === null) return <span className="subtle">기록 없음{user.created_at ? ` · ${formatDate(user.created_at)} 생성` : ''}</span>
  const atRisk = user.active && user.roles.some(r => privileged.includes(r))
  const tone = days >= lockDays ? 'red' : atRisk && days >= lockDays - 14 ? 'amber' : ''
  return <>
    <div>{formatDate(user.last_login_at!)}</div>
    <span className={tone ? `badge ${tone}` : 'subtle'}>{days === 0 ? '오늘' : `${days}일 전`}{tone === 'red' && atRisk ? ' · 잠금 대상' : ''}</span>
  </>
}
