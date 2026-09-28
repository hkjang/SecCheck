import { FormEvent, useEffect, useRef, useState } from 'react'
import { ArrowRight, ChevronDown, KeyRound, Shield, ShieldCheck, Smartphone } from 'lucide-react'
import { post, setCSRF, errorMessage, ApiError } from '../lib/api'
import { safeReturnTo } from '../lib/silentSso'
import { issuerLabel, localFormStartsOpen, rememberLocalLogin } from '../lib/loginChoice'
import { User } from '../lib/types'
import { Button, Field } from '../components/ui'

// The identity provider decides most of these codes, so the ones we know are
// named and anything else is shown as it arrived -- an operator reading a
// screenshot can still look it up.
function ssoMessage(code: string) {
  switch (code) {
    case 'oidc_unavailable': return 'SSO 서버에 연결하지 못했습니다. 잠시 후 다시 시도하고, 계속되면 관리자에게 알려 주세요.'
    case 'oidc': return 'SSO 로그인을 마치지 못했습니다. 다시 시도하거나 아이디와 비밀번호로 로그인하세요.'
    case 'access_denied': return 'SSO에서 로그인이 거부되었습니다. 계정 권한을 관리자에게 확인하세요.'
    default: return `SSO 로그인에 실패했습니다 (${code}). 관리자에게 이 코드를 알려 주세요.`
  }
}

type PublicConfig = { service_name: string; version: string; oidc_enabled: boolean; oidc_auto_login?: boolean; oidc_issuer?: string }

export default function Login({ config, expired, onLogin }: { config: PublicConfig; expired?: boolean; onLogin: (user: User, csrf: string) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [needsTotp, setNeedsTotp] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  // The SSO round trip comes back to this page with a reason in the address
  // bar, and nothing read it: a failed sign-in returned a blank form, so the
  // only thing to do was press the button again and get the same nothing.
  const [ssoError, setSsoError] = useState(() => new URLSearchParams(window.location.search).get('error') || '')
  // A silent attempt that found no provider session lands here with sso=none.
  // That is the ordinary answer for somebody not signed in at the provider,
  // so it explains itself once rather than reading as a failure.
  const [ssoRefused] = useState(() => new URLSearchParams(window.location.search).get('sso') === 'none')
  const [localOpen, setLocalOpen] = useState(() => localFormStartsOpen(config))
  useEffect(() => {
    if (!ssoError) return
    const url = new URL(window.location.href)
    url.searchParams.delete('error')
    window.history.replaceState({}, '', url.toString())
  }, [ssoError])
  // The SSO button carries the place the person was going, so a deep link
  // survives the round trip; after a refused silent attempt that place is in
  // the address of the login screen itself.
  const returnTo = window.location.pathname === '/login' ? safeReturnTo(new URLSearchParams(window.location.search).get('return_to') || '/') : safeReturnTo(window.location.pathname + window.location.search + window.location.hash)
  const totpRef = useRef<HTMLInputElement>(null)
  const localRef = useRef<HTMLInputElement>(null)
  useEffect(() => { if (needsTotp) totpRef.current?.focus() }, [needsTotp])
  const openLocal = () => { setLocalOpen(open => !open); if (!localOpen) window.setTimeout(() => localRef.current?.focus(), 0) }
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setError('')
    try {
      const result = await post<{ user: User; csrf_token: string }>('/api/v1/auth/login', { username, password, totp_code: totp })
      setCSRF(result.csrf_token); rememberLocalLogin(); onLogin(result.user, result.csrf_token)
    } catch (e) {
      // A correct password that still needs its second factor is a prompt, not
      // a failure, so the form grows a field instead of showing an error.
      if (e instanceof ApiError && e.code === 'TOTP_REQUIRED') { setNeedsTotp(true); setError('') }
      else { if (e instanceof ApiError && e.code === 'TOTP_INVALID') setNeedsTotp(true); setError(errorMessage(e)); setTotp('') }
    } finally { setBusy(false) }
  }
  const issuer = issuerLabel(config.oidc_issuer)
  return <div className="login-page"><section className="login-panel"><div className="login-box"><div className="login-brand"><div className="brand-mark"><Shield size={20} /></div><div><strong data-sx="sx-019">SecCheck</strong><div className="subtle">SECURITY REVIEW PLATFORM</div></div></div><h1 className="login-title">안전한 서비스의 시작</h1><p className="login-copy">보안성 심의 체크리스트와 증적, 검토·승인 이력을 하나의 흐름으로 관리합니다.</p>
    {ssoError && <div className="guide-block" role="alert">{ssoMessage(ssoError)}</div>}
    {expired && <div className="guide-block">세션이 종료되어 로그아웃되었습니다. 유휴 시간 초과, 비밀번호 변경 또는 관리자의 세션 종료 때문일 수 있습니다. 다시 로그인하세요.</div>}
    {config.oidc_enabled && ssoRefused && !ssoError && <div className="guide-block" role="status">조직 계정에 로그인되어 있지 않아 자동으로 들어가지 못했습니다. 아래 버튼으로 로그인하세요.</div>}
    {config.oidc_enabled && <div className="login-sso"><a className="button primary login-sso-button" href={`/api/v1/auth/oidc/start?return_to=${encodeURIComponent(returnTo)}`}><ShieldCheck size={17} /> 조직 계정으로 로그인</a><p className="subtle">{issuer ? `${issuer} 에서 인증합니다. 회사에서 쓰는 계정 그대로 사용하세요.` : '회사에서 쓰는 계정 그대로 사용하세요.'}{config.oidc_auto_login ? ' 조직 계정에 이미 로그인해 두면 다음부터 이 화면을 거치지 않습니다.' : ''}</p></div>}
    {config.oidc_enabled && <button type="button" className="login-fallback-toggle" aria-expanded={localOpen} aria-controls="local-login-form" onClick={openLocal}><KeyRound size={16} /><span>아이디·비밀번호로 로그인</span><ChevronDown size={16} className={localOpen ? 'flipped' : ''} /></button>}
    {localOpen && <form id="local-login-form" className="login-form" onSubmit={submit}>
      {config.oidc_enabled && <div className="guide-block">조직 계정을 쓸 수 없을 때를 위한 로그인입니다. 평소에는 위의 조직 계정으로 로그인하세요.</div>}
      <Field label="아이디" required><input ref={localRef} className="input" autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} /></Field>
      <Field label="비밀번호" required error={needsTotp ? '' : error}><input className="input" type="password" autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} /></Field>
      {needsTotp && <Field label="일회용 코드" required help="인증 앱에 표시된 6자리 숫자" error={error}><input ref={totpRef} className="input" inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="000000" value={totp} onChange={e => setTotp(e.target.value.replace(/\D/g, ''))} /></Field>}
      <Button variant="primary" disabled={busy || !username || !password || (needsTotp && totp.length < 6)}>{busy ? '로그인 중…' : needsTotp ? <><Smartphone size={16} /> 코드 확인</> : <>로그인 <ArrowRight size={16} /></>}</Button>
    </form>}</div><div className="login-version">{config.service_name} v{config.version}</div></section>
    <section className="login-visual"><h2>Excel 업무를 넘어<br />추적 가능한 Security Control로.</h2><p>템플릿 버전과 제출 스냅샷을 분리하고, 모든 작성·검토·승인 행위를 감사 가능한 이력으로 보존합니다.</p><div className="visual-flow"><div className="flow-node">심의 요청</div><span className="flow-arrow">→</span><div className="flow-node">체크리스트 작성</div><span className="flow-arrow">→</span><div className="flow-node">검토 · 승인</div></div></section></div>
}
