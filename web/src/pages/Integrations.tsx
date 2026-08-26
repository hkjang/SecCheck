import { useEffect, useState } from 'react'
import { Copy, ExternalLink, Sparkles } from 'lucide-react'
import { get } from '../lib/api'
import { Badge, Button, LoadFailed, Loading, useToast } from '../components/ui'
import { useAuth } from '../main'

type Integration = {
  api_version: string; openapi: string; mcp_endpoint: string; mcp_version: string; mcp_compatibility: string[]
  tools: { name: string; title: string; description: string; read_only: boolean }[]
}

export default function Integrations() {
  const { version } = useAuth()
  const toast = useToast()
  const [info, setInfo] = useState<Integration>()
  // The tool list is served rather than written here: the hard-coded copy had
  // drifted to five entries while seven were being offered.
  const [failed, setFailed] = useState<unknown>()
  const load = () => { setFailed(undefined); return get<Integration>('/api/v1/integrations').then(setInfo).catch(setFailed) }
  useEffect(() => { load() }, [])
  const copy = (value: string) => { navigator.clipboard.writeText(value); toast.push('클립보드에 복사했습니다.') }
  const endpoint = `${location.origin}${info?.mcp_endpoint || '/mcp'}`

  return <div className="page">
    <div className="page-header"><div><h1 className="page-title">API · MCP 연계</h1><p className="page-description">Security, IT, AI 자동화를 위한 인증된 인터페이스입니다.</p></div><a className="button" href="/api/openapi.json" target="_blank" rel="noreferrer"><ExternalLink size={14} /> OpenAPI 3.1</a></div>
    <div className="grid two">
      <section className="card"><div className="card-header"><h2>REST API</h2><Badge tone="blue">{info?.api_version || 'v1'}</Badge></div><div className="card-body">
        <p className="subtle" data-sx="sx-023">브라우저 세션은 CSRF 보호를 사용하고 시스템 연계는 개인 키의 Bearer 인증을 사용합니다. 모든 API가 Backend에서 RBAC와 객체 접근 권한을 다시 검증합니다.</p>
        <div className="guide-block">Authorization: Bearer sck_…</div>
        <pre className="guide-block" data-sx="sx-043">{`curl -H "Authorization: Bearer $KEY" \\\n  ${location.origin}/api/v1/review-requests`}</pre>
        <p className="subtle">명세는 서버의 라우트 등록 테이블에서 생성되므로 모든 엔드포인트가 포함되며, operation마다 필요한 역할이 <code>x-required-roles</code>로 표기됩니다.</p>
        <a className="button" href="/api/openapi.json" target="_blank" rel="noreferrer"><ExternalLink size={14} /> 명세 열기</a>
      </div></section>
      <section className="card"><div className="card-header"><h2>Model Context Protocol</h2><Badge tone="green">{info?.mcp_version || '—'}</Badge></div><div className="card-body">
        <p className="subtle" data-sx="sx-023">최신 Stateless Streamable HTTP를 지원하며, 구형 {(info?.mcp_compatibility || []).join(', ') || '이전'} initialize 클라이언트도 호환합니다. 개인 API 키를 Authorization 헤더에 설정하세요.</p>
        <div className="field"><label>Endpoint</label><div data-sx="sx-004"><input className="input" readOnly value={endpoint} /><Button aria-label="MCP 엔드포인트 주소 복사" onClick={() => copy(endpoint)}><Copy size={14} /></Button></div></div>
        <div data-sx="sx-029"><strong data-sx="sx-018">제공 도구 {info ? `(${info.tools.length})` : ''}</strong>
          {failed ? <LoadFailed error={failed} onRetry={load} /> : !info ? <Loading /> : <div className="table-wrap"><table><caption className="sr-only">제공 중인 MCP 도구</caption><tbody>{info.tools.map(tool => <tr key={tool.name}><td><code>{tool.name}</code>{tool.read_only && <Badge tone="green">읽기 전용</Badge>}<div className="subtle">{tool.description}</div></td></tr>)}</tbody></table></div>}
        </div>
      </div></section>
    </div>
    <section className="card" data-sx="sx-030"><div className="card-header"><h2><Sparkles size={17} /> AI 연계 안전 원칙</h2></div><div className="card-body">
      <div className="grid three">{[['최소 권한', '사용자의 API 키 권한과 심의 Row 접근 범위가 MCP에도 동일하게 적용됩니다.'], ['읽기 전용 도구', '현재 MCP 도구는 조회·검증 전용이며, 상태 변경은 서비스 UI에서 사람이 확인합니다.'], ['완전한 감사', 'MCP 도구 호출도 사용자, 도구명, 요청 ID와 함께 감사로그에 기록됩니다.']].map(([title, body]) => <div className="toggle-row" key={title}><div><strong>{title}</strong><div className="subtle" data-sx="sx-034">{body}</div></div></div>)}</div>
      <p className="subtle" data-sx="sx-031">SecCheck v{version}</p>
    </div></section>
  </div>
}
