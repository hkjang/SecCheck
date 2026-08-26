import { useState } from 'react'
import { FlaskConical, Play } from 'lucide-react'
import { errorMessage, post } from '../lib/api'
import { Badge, Button, Empty, Field, Loading, Toggle, useToast } from '../components/ui'

type Condition = { field: string; operator: string; value: unknown; actual: unknown; matched: boolean; negated: boolean }
type Outcome = { template: string; version: string; item_code: string; category: string; title: string; severity: string; applied: boolean; reason: string; rule_error?: string; conditions?: Condition[] }
type Result = { applied: number; excluded: number; broken?: number; templates: { template: string; applied: number; total: number }[]; items: Outcome[] }

const profileToggles: [string, string][] = [
  ['has_admin_page', '관리자 페이지 있음'], ['processes_personal_data', '개인정보 처리'], ['processes_credit_data', '신용정보 처리'],
  ['external_customer_service', '대외 고객 서비스'], ['uses_cloud', '클라우드 사용'], ['uses_docker', 'Docker 사용'],
  ['uses_kubernetes', 'Kubernetes 사용'], ['external_integration', '외부 연계'], ['internet_access', '인터넷 접점'],
]


// The rule speaks in field names; the form the requester fills in speaks
// Korean, and the reader is comparing the two.
const fieldLabels: Record<string, string> = {
  service_type: '서비스 유형', change_type: '변경 유형', exposure: '노출 구분', business_criticality: '업무 중요도',
  has_admin_page: '관리자 페이지 있음', processes_personal_data: '개인정보 처리', processes_credit_data: '신용정보 처리',
  external_customer_service: '대외 고객 서비스', uses_cloud: '클라우드 사용', uses_docker: 'Docker 사용',
  uses_kubernetes: 'Kubernetes 사용', external_integration: '외부 연계', internet_access: '인터넷 접점',
}
const operatorText: Record<string, string> = { eq: '=', '=': '=', neq: '≠', '!=': '≠', in: '중 하나', contains: '포함', gt: '>', gte: '≥', lt: '<', lte: '≤', exists: '값 존재' }
const conditionText = (v: unknown) => typeof v === 'boolean' ? (v ? '예' : '아니오') : Array.isArray(v) ? v.join(', ') : String(v ?? '')
// A condition reads as "개인정보 처리 = 예 (현재 아니오)": what the rule asks
// for, and what this service actually says.
function Conditions({ list }: { list: Condition[] }) {
  if (!list.length) return null
  return <ul className="subtle" data-sx="sx-006">{list.map((c, i) => <li key={i}>
    {c.matched ? '✓' : '✗'} {c.negated ? '아님: ' : ''}{fieldLabels[c.field] || c.field} {operatorText[c.operator] || c.operator} {conditionText(c.value)}
    {!c.matched && <> — 현재 {conditionText(c.actual)}</>}
  </li>)}</ul>
}

export default function RuleSimulator() {
  const toast = useToast()
  const [profile, setProfile] = useState<Record<string, unknown>>({
    service_name: '시뮬레이션', description: '규칙 검증', service_type: 'WEB', change_type: 'NEW',
    department: '보안팀', exposure: 'EXTERNAL', business_criticality: 'HIGH',
    has_admin_page: true, processes_personal_data: true, processes_credit_data: false,
    external_customer_service: true, uses_cloud: false, uses_docker: false,
    uses_kubernetes: false, external_integration: false, internet_access: true,
  })
  const [result, setResult] = useState<Result>()
  const [busy, setBusy] = useState(false)
  const [showExcluded, setShowExcluded] = useState(false)
  const set = (key: string, value: unknown) => setProfile(v => ({ ...v, [key]: value }))
  const run = async () => {
    setBusy(true)
    try { setResult(await post<Result>('/api/v1/templates/rule-simulation', profile)) }
    catch (e) { toast.push(errorMessage(e), 'error') } finally { setBusy(false) }
  }
  const shown = (result?.items || []).filter(i => showExcluded || i.applied)
  const brokenItems = (result?.items || []).filter(i => i.rule_error)
  return <div className="page">
    <div className="page-header"><div><h1 className="page-title">Rule Engine 시뮬레이터</h1><p className="page-description">심의를 만들지 않고 서비스 특성만으로 어떤 체크리스트가 배정되는지 확인합니다. 게시 버전은 수정할 수 없으므로 게시 전에 규칙을 검증하세요.</p></div><Button variant="primary" disabled={busy} onClick={run}><Play size={14} /> {busy ? '계산 중…' : '시뮬레이션 실행'}</Button></div>

    <section className="card"><div className="card-header"><h2><FlaskConical size={17} /> 서비스 특성</h2></div><div className="card-body">
      <div className="form-grid">
        <Field label="서비스 유형"><select className="select" value={String(profile.service_type)} onChange={e => set('service_type', e.target.value)}><option>WEB</option><option>APP</option><option>API</option><option>BATCH</option><option>INFRA</option></select></Field>
        <Field label="변경 유형"><select className="select" value={String(profile.change_type)} onChange={e => set('change_type', e.target.value)}><option>NEW</option><option>CHANGE</option><option>RENEWAL</option></select></Field>
        <Field label="노출 범위"><select className="select" value={String(profile.exposure)} onChange={e => set('exposure', e.target.value)}><option>EXTERNAL</option><option>INTERNAL</option><option>PARTNER</option></select></Field>
        <Field label="중요도"><select className="select" value={String(profile.business_criticality)} onChange={e => set('business_criticality', e.target.value)}><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></Field>
      </div>
      <div className="grid two">{profileToggles.map(([key, label]) => <Toggle key={key} label={label} value={Boolean(profile[key])} onChange={v => set(key, v)} />)}</div>
    </div></section>

    {busy && !result ? <Loading /> : result ? <>
      <div className="grid stats">
        <div className="card stat-card"><div className="stat-icon green"><Play /></div><div><span className="stat-value">{result.applied}</span><div className="stat-label">배정될 항목</div></div></div>
        <div className="card stat-card"><div className="stat-icon"><FlaskConical /></div><div><span className="stat-value">{result.excluded}</span><div className="stat-label">제외될 항목</div></div></div>
      </div>
      {brokenItems.length > 0 && <section className="card"><div className="card-header"><h2>적용 규칙 오류</h2><Badge tone="red">{brokenItems.length}개</Badge></div>
        <div className="card-body"><p className="subtle">아래 항목은 적용 규칙이 심의 입력에 없는 값을 가리키고 있어, 이 프로필뿐 아니라 <strong>어떤 심의에도 배정되지 않습니다</strong>. 게시된 버전은 수정할 수 없으므로 새 버전에서 규칙을 고쳐야 합니다.</p></div>
        <div className="table-wrap"><table><caption className="sr-only">적용 규칙 오류 목록</caption><thead><tr><th scope="col">항목코드</th><th scope="col">템플릿</th><th scope="col">보안요건</th><th scope="col">오류</th></tr></thead>
          <tbody>{brokenItems.map((item, i) => <tr key={`broken-${item.template}-${item.item_code}-${i}`}><td><code>{item.item_code}</code></td><td className="subtle">{item.template} {item.version}</td><td>{item.title}</td><td>{item.rule_error}</td></tr>)}</tbody></table></div></section>}
      <section className="card"><div className="card-header"><h2>템플릿별 배정</h2><button type="button" className={`chip ${showExcluded ? 'on' : ''}`} aria-pressed={showExcluded} onClick={() => setShowExcluded(!showExcluded)}>제외 항목도 보기</button></div>
        <div className="table-wrap"><table><caption className="sr-only">템플릿별 배정 결과</caption><thead><tr><th scope="col">템플릿</th><th scope="col">배정 / 전체</th></tr></thead><tbody>{result.templates.map(t => <tr key={t.template}><td>{t.template}</td><td><Badge tone={t.applied ? 'green' : ''}>{t.applied} / {t.total}</Badge></td></tr>)}</tbody></table></div></section>
      <section className="card"><div className="card-header"><h2>항목별 결과</h2><Badge>{shown.length}개</Badge></div>
        {shown.length ? <div className="table-wrap"><table><caption className="sr-only">항목별 적용 여부</caption><thead><tr><th scope="col">항목코드</th><th scope="col">템플릿</th><th scope="col">보안요건</th><th scope="col">중요도</th><th scope="col">결과</th></tr></thead>
          <tbody>{shown.map((item, i) => <tr key={`${item.template}-${item.item_code}-${i}`}><td><code>{item.item_code}</code></td><td className="subtle">{item.template} {item.version}</td><td>{item.title}</td><td>{item.severity}</td><td>{item.applied ? <><Badge tone="green">배정</Badge>{item.conditions?.length ? <Conditions list={item.conditions} /> : null}</> : <><Badge>제외</Badge><div className="subtle">{item.reason}</div>{item.conditions?.length ? <Conditions list={item.conditions.filter(c => !c.matched)} /> : null}</>}</td></tr>)}</tbody></table></div>
          : <Empty title="배정되는 항목이 없습니다." description="서비스 특성을 조정하거나 템플릿의 적용 규칙을 확인하세요." />}</section>
    </> : null}
  </div>
}
