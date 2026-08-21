import { FormEvent, useEffect, useRef, useState } from 'react'
import { ArrowRight, KeyRound, Shield, Smartphone } from 'lucide-react'
import { post, setCSRF, errorMessage, ApiError } from '../lib/api'
import { User } from '../lib/types'
import { Button, Field } from '../components/ui'

export default function Login({ config, onLogin }: { config: { service_name: string; version: string; oidc_enabled: boolean }; onLogin: (user: User, csrf: string) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [needsTotp, setNeedsTotp] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const totpRef = useRef<HTMLInputElement>(null)
  useEffect(() => { if (needsTotp) totpRef.current?.focus() }, [needsTotp])
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setError('')
    try {
      const result = await post<{ user: User; csrf_token: string }>('/api/v1/auth/login', { username, password, totp_code: totp })
      setCSRF(result.csrf_token); onLogin(result.user, result.csrf_token)
    } catch (e) {
      // A correct password that still needs its second factor is a prompt, not
      // a failure, so the form grows a field instead of showing an error.
      if (e instanceof ApiError && e.code === 'TOTP_REQUIRED') { setNeedsTotp(true); setError('') }
      else { if (e instanceof ApiError && e.code === 'TOTP_INVALID') setNeedsTotp(true); setError(errorMessage(e)); setTotp('') }
    } finally { setBusy(false) }
  }
  return <div className="login-page"><section className="login-panel"><div className="login-box"><div className="login-brand"><div className="brand-mark"><Shield size={20} /></div><div><strong data-sx="sx-019">SecCheck</strong><div className="subtle">SECURITY REVIEW PLATFORM</div></div></div><h1 className="login-title">안전한 서비스의 시작</h1><p className="login-copy">보안성 심의 체크리스트와 증적, 검토·승인 이력을 하나의 흐름으로 관리합니다.</p>
    <form className="login-form" onSubmit={submit}>
      <Field label="아이디" required><input className="input" autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} /></Field>
      <Field label="비밀번호" required error={needsTotp ? '' : error}><input className="input" type="password" autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} /></Field>
      {needsTotp && <Field label="일회용 코드" required help="인증 앱에 표시된 6자리 숫자" error={error}><input ref={totpRef} className="input" inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="000000" value={totp} onChange={e => setTotp(e.target.value.replace(/\D/g, ''))} /></Field>}
      <Button variant="primary" disabled={busy || !username || !password || (needsTotp && totp.length < 6)}>{busy ? '로그인 중…' : needsTotp ? <><Smartphone size={16} /> 코드 확인</> : <>로그인 <ArrowRight size={16} /></>}</Button>
    </form>
    {config.oidc_enabled && <><div className="login-separator">또는</div><a className="button" href="/api/v1/auth/oidc/start"><KeyRound size={16} /> 사내 SSO로 로그인</a></>}</div><div className="login-version">{config.service_name} v{config.version}</div></section>
    <section className="login-visual"><h2>Excel 업무를 넘어<br />추적 가능한 Security Control로.</h2><p>템플릿 버전과 제출 스냅샷을 분리하고, 모든 작성·검토·승인 행위를 감사 가능한 이력으로 보존합니다.</p><div className="visual-flow"><div className="flow-node">심의 요청</div><span className="flow-arrow">→</span><div className="flow-node">체크리스트 작성</div><span className="flow-arrow">→</span><div className="flow-node">검토 · 승인</div></div></section></div>
}
