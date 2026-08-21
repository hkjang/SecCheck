import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { Activity, Bell, BookOpen, Boxes, CheckSquare, ChevronDown, ClipboardCheck, FileKey, Gauge, History, KeyRound, LayoutDashboard, ListChecks, Lock, Logs, ListTodo, Search, Settings, Shield, ShieldCheck, Sparkles, Users, X } from 'lucide-react'
import { useAuth } from '../main'
import { Button, Modal } from './ui'
import { get } from '../lib/api'

type Nav = { to: string; label: string; icon: typeof Gauge; roles?: string[]; section?: string }
const navigation: Nav[] = [
  { to: '/', label: '대시보드', icon: LayoutDashboard, section: '업무' },
  { to: '/reviews', label: '내 심의', icon: ClipboardCheck },
  { to: '/reviews/new', label: '신규 심의 요청', icon: CheckSquare, roles: ['REQUESTER'] },
  { to: '/security', label: '보안 검토 Queue', icon: Shield, roles: ['SECURITY_REVIEWER'], section: '검토' },
  { to: '/templates', label: '체크리스트 템플릿', icon: ListChecks, roles: ['TEMPLATE_ADMIN'], section: '관리' },
  { to: '/templates/import', label: 'Excel 가져오기', icon: Boxes, roles: ['TEMPLATE_ADMIN'] },
  { to: '/controls', label: 'Security Controls', icon: ShieldCheck, roles: ['TEMPLATE_ADMIN', 'SECURITY_REVIEWER', 'AUDITOR'] },
  { to: '/admin/users', label: '사용자·역할', icon: Users, roles: ['SYSTEM_ADMIN'] },
  { to: '/admin/settings', label: '서비스 설정', icon: Settings, roles: ['SYSTEM_ADMIN'] },
  { to: '/admin/audit', label: '감사로그', icon: History, roles: ['SYSTEM_ADMIN', 'AUDITOR'] },
  { to: '/admin/logs', label: '서버 로그', icon: Logs, roles: ['SYSTEM_ADMIN'] },
  { to: '/admin/jobs', label: '작업 큐', icon: ListTodo, roles: ['SYSTEM_ADMIN'] },
  { to: '/profile/security', label: '계정 보안', icon: Lock, section: '개인화' },
  { to: '/profile/keys', label: '개인 키 관리', icon: FileKey },
  { to: '/integrations', label: 'API · MCP', icon: Sparkles },
]

const titles: Record<string, [string, string]> = {
  '/': ['대시보드', 'SecCheck 보안성 심의 현황'], '/reviews': ['심의 관리', '작성·제출·보완 상태를 관리합니다'], '/reviews/new': ['신규 심의', '서비스 정보를 기준으로 체크리스트가 자동 배정됩니다'], '/security': ['보안 검토 Queue', '신규 제출과 보완 건을 검토합니다'], '/controls': ['Security Controls', '중복 통제를 통합하고 영향 범위를 추적합니다'], '/templates': ['템플릿 관리', '체크리스트 원본과 게시 버전을 관리합니다'], '/templates/import': ['Excel 가져오기', '기존 체크리스트를 검증 후 템플릿으로 전환합니다'], '/admin/users': ['사용자·역할', 'RBAC 사용자와 최소 권한을 관리합니다'], '/admin/settings': ['서비스 관리자 설정', '운영 설정과 OIDC를 중앙 관리합니다'], '/admin/audit': ['감사로그', '중요 행위의 해시 체인 이력을 확인합니다'], '/admin/logs': ['서버 로그', '구조화된 애플리케이션 로그를 확인합니다'], '/admin/jobs': ['작업 큐', '알림과 증적 검사 작업을 확인하고 재시도합니다'], '/profile/keys': ['개인 키 관리', '개인 API 키와 암호화 키를 회전합니다'], '/profile/security': ['계정 보안', '일회용 코드와 로그인 세션을 관리합니다'], '/integrations': ['API · MCP', '보안 자동화와 AI 에이전트 연계를 구성합니다']
}

export default function Layout() {
  const { user, version, logout } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  const [profile, setProfile] = useState(false)
  const [command, setCommand] = useState(false)
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<{ reviews?: Record<string, string>[]; items?: Record<string, string>[]; evidences?: Record<string, string>[] }>({})
  const [unread, setUnread] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const visible = useMemo(() => navigation.filter(n => !n.roles || n.roles.some(r => user.roles.includes(r))), [user.roles])
  const pathTitle = location.pathname.startsWith('/reviews/') && location.pathname !== '/reviews/new' ? ['심의 상세', '체크리스트 작성과 검토 이력을 확인합니다'] : location.pathname.startsWith('/templates/') && location.pathname !== '/templates/import' ? ['템플릿 편집', '초안 항목과 버전을 관리합니다'] : titles[location.pathname] || ['SecCheck', '보안성 심의 관리']
  useEffect(() => { const key = (e: KeyboardEvent) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setCommand(true) } }; window.addEventListener('keydown', key); return () => window.removeEventListener('keydown', key) }, [])
  useEffect(() => { if (command) window.setTimeout(() => inputRef.current?.focus(), 40) }, [command])
  useEffect(() => { const timer = window.setTimeout(async () => { if (query.trim().length >= 2) setResults(await get(`/api/v1/search?q=${encodeURIComponent(query)}`)); else setResults({}) }, 250); return () => clearTimeout(timer) }, [query])
  // The badge refreshes on every navigation and once a minute, so a reviewer
  // sees a new assignment without having to open the notifications page.
  useEffect(() => { let alive = true; const poll = () => get<{ count: number }>('/api/v1/notifications/unread-count').then(v => { if (alive) setUnread(v.count) }).catch(() => undefined); poll(); const timer = window.setInterval(poll, 60000); return () => { alive = false; clearInterval(timer) } }, [location.pathname])
  let lastSection = ''
  return <div className="app-shell">
    <aside className="sidebar">
      <Link to="/" className="brand"><div className="brand-mark"><Shield size={20} /></div><div className="brand-text"><strong>SecCheck</strong><small>SECURITY REVIEW</small></div></Link>
      <nav className="nav-scroll">{visible.map(item => { const section = item.section && item.section !== lastSection ? item.section : ''; if (item.section) lastSection = item.section; const Icon = item.icon; return <div key={item.to}>{section && <div className="nav-section">{section}</div>}<NavLink to={item.to} end={item.to === '/'} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Icon /><span>{item.label}</span></NavLink></div> })}</nav>
      <div className="sidebar-footer"><button className="quick-button" onClick={() => setCommand(true)}><span><Search size={14} /> 빠른 이동</span><kbd>Ctrl K</kbd></button></div>
    </aside>
    <main className="content-shell">
      <header className="topbar"><div className="topbar-title"><strong>{pathTitle[0]}</strong><span>{pathTitle[1]}</span></div><div className="top-actions"><Link to="/admin/logs" className="icon-button" aria-label="운영 상태"><Activity size={18} /></Link><Link to="/notifications" className="icon-button with-badge" aria-label={unread ? `읽지 않은 알림 ${unread}건` : '알림'}><Bell size={18} />{unread > 0 && <span className="icon-badge">{unread > 99 ? '99+' : unread}</span>}</Link><button className="profile-button" onClick={() => setProfile(v => !v)}><div className="avatar">{user.display_name.slice(0, 1)}</div><div className="profile-meta"><strong>{user.display_name}</strong><span>{user.department || user.username}</span></div><ChevronDown size={15} /></button>{profile && <div className="profile-menu"><Link to="/profile" onClick={() => setProfile(false)}><Users size={16} /> 프로필</Link><Link to="/profile/security" onClick={() => setProfile(false)}><Lock size={16} /> 계정 보안</Link><Link to="/profile/keys" onClick={() => setProfile(false)}><KeyRound size={16} /> 개인 키 관리</Link><button onClick={logout}><X size={16} /> 로그아웃</button><div className="profile-version">SecCheck v{version}</div></div>}</div></header>
      <Outlet />
    </main>
    {command && <Modal onClose={() => { setCommand(false); setQuery(''); setResults({}) }} className="command-modal"><div data-sx="sx-026"><Search data-sx="sx-047" size={20} /><input ref={inputRef} className="command-input" placeholder="메뉴, 심의번호, 서비스명, 보안항목, 증적 검색…" value={query} onChange={e => setQuery(e.target.value)} /><div className="command-list">{!query && visible.map(item => { const Icon = item.icon; return <button className="command-item" key={item.to} onClick={() => { navigate(item.to); setCommand(false) }}><Icon size={18} /><span>{item.label}</span></button> })}{results.reviews?.map(x => <button className="command-item" key={x.id} onClick={() => { navigate(`/reviews/${x.id}`); setCommand(false) }}><ClipboardCheck size={18} /><span><strong>{x.review_number}</strong> {x.service_name}</span></button>)}{results.items?.map((x, i) => <button className="command-item" key={`${x.review_id}-${i}`} onClick={() => { navigate(`/reviews/${x.review_id}`); setCommand(false) }}><BookOpen size={18} /><span><strong>{x.item_code}</strong> {x.title}</span></button>)}{results.evidences?.map(x=><button className="command-item" key={x.id} onClick={()=>{navigate(`/reviews/${x.review_id}`);setCommand(false)}}><FileKey size={18}/><span><strong>{x.review_number}</strong> {x.original_filename}</span></button>)}</div></div></Modal>}
  </div>
}
