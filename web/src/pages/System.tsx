import { useEffect, useState } from 'react'
import { Database, HardDrive, RefreshCw } from 'lucide-react'
import { get } from '../lib/api'
import { Badge, Button, formatBytes, formatDate, LoadFailed, Loading } from '../components/ui'

type Storage = { path: string; writable: boolean; free_bytes: number; total_bytes: number; detail?: string }
type Coverage = { code: string; active: number; total: number }
type Integrity = { checked: number; unchecked: number; failed: number; oldest_checked_at?: string; failures: { filename: string; review_number: string; reason: string; checked_at?: string }[] }
type Info = {
  version: string; schema_version: number; go_version: string
  users: number; reviews: number; templates: number; evidences: number; logs: number
  database_size: string; pdf_font: string; pdf_export_available: boolean; storage: Storage; role_coverage: Coverage[]; evidence_integrity: Integrity; now: string
}

const roleLabel: Record<string, string> = { SYSTEM_ADMIN: '서비스 관리자', SECURITY_REVIEWER: '보안 담당자', APPROVER: '승인자', TEMPLATE_ADMIN: '체크리스트 관리자', AUDITOR: '감사' }

// The endpoint behind this screen has always existed and nothing showed it, so
// the schema version an upgrade note refers to and the Korean font a PDF
// export needs could only be read with curl.
export default function SystemPage() {
  const [info, setInfo] = useState<Info>()
  const [failed, setFailed] = useState<unknown>()
  const load = () => { setFailed(undefined); get<Info>('/api/v1/admin/system').then(setInfo).catch(setFailed) }
  useEffect(load, [])
  if (failed) return <LoadFailed error={failed} onRetry={load} />
  if (!info) return <Loading />
  const free = info.storage.total_bytes > 0 ? info.storage.free_bytes / info.storage.total_bytes : 0
  const storageTone = !info.storage.writable ? 'red' : free < 0.1 ? 'amber' : 'green'
  // An installation upgraded mid-cycle has no verification history yet, so the
  // card has to read as "not checked", not as a failure.
  const integrity: Integrity = info.evidence_integrity || { checked: 0, unchecked: 0, failed: 0, failures: [] }
  const rows: [string, React.ReactNode][] = [
    ['버전', info.version],
    ['스키마 버전', String(info.schema_version)],
    ['Go 런타임', info.go_version],
    ['서버 시각', formatDate(info.now, true)],
    ['데이터베이스 크기', info.database_size],
    ['PDF 내보내기', info.pdf_export_available ? <Badge tone="green">사용 가능</Badge> : <><Badge tone="red">불가</Badge> <span className="subtle">한글 글꼴이 image에 없습니다</span></>],
    ['PDF 글꼴', info.pdf_font || '-'],
  ]
  const counts: [string, number][] = [['사용자', info.users], ['심의', info.reviews], ['템플릿', info.templates], ['증적', info.evidences], ['서버 로그', info.logs]]
  return <div className="page">
    <div className="page-header"><div><h1 className="page-title">시스템 정보</h1><p className="page-description">업그레이드와 장애 대응에서 먼저 확인하는 값입니다.</p></div><div className="header-actions"><Button onClick={load}><RefreshCw size={14} /> 새로고침</Button></div></div>
    <div className="grid stats">
      <div className="card stat-card"><div className={`stat-icon ${storageTone === 'green' ? 'green' : ''}`}><HardDrive /></div><div><span className="stat-value">{info.storage.total_bytes > 0 ? formatBytes(info.storage.free_bytes) : '-'}</span><div className="stat-label">증적 볼륨 남은 공간</div></div></div>
      <div className="card stat-card"><div className="stat-icon"><Database /></div><div><span className="stat-value">{info.database_size}</span><div className="stat-label">데이터베이스 크기</div></div></div>
    </div>
    <section className="card"><div className="card-header"><h2>증적 저장소</h2><Badge tone={storageTone}>{info.storage.writable ? (free < 0.1 ? '여유 부족' : '정상') : '쓰기 불가'}</Badge></div>
      <div className="table-wrap"><table><tbody>
        <tr><th>경로</th><td><code>{info.storage.path}</code></td></tr>
        <tr><th>쓰기 가능</th><td>{info.storage.writable ? '예' : `아니오${info.storage.detail ? ` · ${info.storage.detail}` : ''}`}</td></tr>
        <tr><th>남은 공간</th><td>{info.storage.total_bytes > 0 ? `${formatBytes(info.storage.free_bytes)} / ${formatBytes(info.storage.total_bytes)} (${(free * 100).toFixed(0)}%)` : '측정할 수 없습니다'}</td></tr>
      </tbody></table></div>
      {(!info.storage.writable || free < 0.1) && <div className="card-body"><p className="subtle">공간이 떨어지거나 볼륨에 쓸 수 없게 되면 증적 업로드가 실패합니다. 시스템 관리자에게 `저장 공간 부족` 알림이 발송됩니다.</p></div>}
    </section>
    <section className="card"><div className="card-header"><h2>증적 무결성</h2><Badge tone={integrity.failed > 0 ? 'red' : integrity.checked > 0 ? 'green' : 'amber'}>{integrity.failed > 0 ? `${integrity.failed}건 확인 실패` : integrity.checked > 0 ? '정상' : '확인 이력 없음'}</Badge></div>
      <div className="table-wrap"><table><tbody>
        <tr><th>확인한 증적</th><td>{integrity.checked.toLocaleString()}건 · 미확인 {integrity.unchecked.toLocaleString()}건</td></tr>
        <tr><th>가장 오래된 확인</th><td>{integrity.oldest_checked_at ? formatDate(integrity.oldest_checked_at, true) : '-'}</td></tr>
      </tbody></table></div>
      {integrity.failures.length > 0 && <div className="table-wrap"><table><thead><tr><th>파일</th><th>심의</th><th>사유</th><th>확인 시각</th></tr></thead><tbody>{integrity.failures.map((f, i) => <tr key={i}><td>{f.filename}</td><td>{f.review_number || '-'}</td><td>{f.reason}</td><td>{formatDate(f.checked_at, true)}</td></tr>)}</tbody></table></div>}
      <div className="card-body"><p className="subtle">유지보수 스윕이 매시 가장 오래 확인하지 않은 증적을 복호화해 크기와 해시를 대조합니다. 실패한 파일은 백업본 복구가 필요하며, 전체 점검은 <code>seccheck verify-evidence</code>로 실행합니다.</p></div>
    </section>
    <section className="card"><div className="card-header"><h2>역할 보유자</h2></div>
      <div className="card-body"><p className="subtle">본인이 신청한 심의는 본인이 검토·승인할 수 없으므로, 검토자와 승인자가 한 명뿐이면 그 사람이 신청한 건은 처리할 수 없습니다.</p></div>
      <div className="table-wrap"><table><thead><tr><th scope="col">역할</th><th scope="col">활성 계정</th><th scope="col">전체</th><th scope="col"></th></tr></thead>
        <tbody>{(info.role_coverage || []).map(role => <tr key={role.code}><td>{roleLabel[role.code] || role.code}</td><td>{role.active}</td><td className="subtle">{role.total}</td>
          <td>{role.active === 0 ? <Badge tone="red">담당자 없음</Badge> : role.active === 1 ? <Badge tone="amber">1명뿐</Badge> : null}</td></tr>)}</tbody></table></div></section>
    <section className="card"><div className="card-header"><h2>런타임</h2></div>
      <div className="table-wrap"><table><tbody>{rows.map(([label, value]) => <tr key={label}><th>{label}</th><td>{value}</td></tr>)}</tbody></table></div></section>
    <section className="card"><div className="card-header"><h2>데이터 규모</h2></div>
      <div className="table-wrap"><table><thead><tr><th scope="col">항목</th><th scope="col">건수</th></tr></thead>
        <tbody>{counts.map(([label, value]) => <tr key={label}><td>{label}</td><td>{value.toLocaleString('ko-KR')}</td></tr>)}</tbody></table></div></section>
  </div>
}
