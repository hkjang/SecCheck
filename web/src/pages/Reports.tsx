import { useEffect, useMemo, useState } from 'react'
import { BarChart3, CalendarRange, Download, Timer } from 'lucide-react'
import { errorMessage, get } from '../lib/api'
import { Badge, Button, Empty, Field, Loading, StatusBadge, useDownload, useToast } from '../components/ui'

type Row = Record<string, string | number>
type Report = {
  from: string; to: string
  totals: { created: number; submitted: number; completed: number; rejected: number; in_progress: number }
  cycle_time: { measured: number; average_days: number; median_days: number; p90_days: number }
  by_status: Row[]; by_department: Row[]; by_result: Row[]; recurring_findings: Row[]; aging: Row[]
}
const resultLabel: Record<string, string> = { COMPLIANT: '적합', CONDITIONAL: '조건부 적합', INSUFFICIENT: '미흡', NON_COMPLIANT: '부적합', NA_ACCEPTED: 'N/A 인정', RECHECK: '재확인' }

// Defaulting to the current month is what a monthly report actually needs.
function monthStart() { const d = new Date(); return new Date(d.getFullYear(), d.getMonth(), 1).toISOString().slice(0, 10) }
function today() { return new Date().toISOString().slice(0, 10) }

export default function Reports() {
  const toast = useToast()
  const save = useDownload()
  const [filter, setFilter] = useState({ from: monthStart(), to: today(), department: '' })
  const [data, setData] = useState<Report>()
  const params = useMemo(() => { const qs = new URLSearchParams(); Object.entries(filter).forEach(([k, v]) => { if (v) qs.set(k, v) }); return qs }, [filter])
  useEffect(() => { setData(undefined); const timer = window.setTimeout(() => { get<Report>(`/api/v1/reports/reviews?${params}`).then(setData).catch(e => toast.push(errorMessage(e), 'error')) }, 200); return () => clearTimeout(timer) }, [params])
  const set = (key: keyof typeof filter, value: string) => setFilter(v => ({ ...v, [key]: value }))
  const preset = (months: number) => { const d = new Date(); const start = new Date(d.getFullYear(), d.getMonth() - months + 1, 1); setFilter(v => ({ ...v, from: start.toISOString().slice(0, 10), to: today() })) }

  return <div className="page">
    <div className="page-header"><div><h1 className="page-title">심의 리포트</h1><p className="page-description">기간별 심의 처리 현황과 반복 지적 사항을 집계합니다. 보고용 Excel로 내려받을 수 있습니다.</p></div>
      <Button variant="primary" onClick={() => save(`/api/v1/reports/reviews?${new URLSearchParams({ ...Object.fromEntries(params), format: 'xlsx' })}`)}><Download size={14} /> Excel 리포트</Button></div>

    <div className="card"><div className="card-body"><div className="form-grid compact">
      <Field label="시작일"><input type="date" className="input" max={filter.to} value={filter.from} onChange={e => set('from', e.target.value)} /></Field>
      <Field label="종료일"><input type="date" className="input" min={filter.from} value={filter.to} onChange={e => set('to', e.target.value)} /></Field>
      <Field label="부서" help="비우면 전체"><input className="input" value={filter.department} onChange={e => set('department', e.target.value)} /></Field>
      <div className="field"><label>기간 선택</label><div className="header-actions"><Button small onClick={() => preset(1)}>이번 달</Button><Button small onClick={() => preset(3)}>최근 3개월</Button><Button small onClick={() => preset(12)}>최근 1년</Button></div></div>
    </div></div></div>

    {!data ? <Loading /> : <>
      <div className="grid stats">
        <div className="card stat-card"><div className="stat-icon"><CalendarRange /></div><div><span className="stat-value">{data.totals.created}</span><div className="stat-label">신규 심의</div></div></div>
        <div className="card stat-card"><div className="stat-icon green"><BarChart3 /></div><div><span className="stat-value">{data.totals.completed}</span><div className="stat-label">완료</div></div></div>
        <div className="card stat-card"><div className="stat-icon amber"><BarChart3 /></div><div><span className="stat-value">{data.totals.in_progress}</span><div className="stat-label">진행 중</div></div></div>
        <div className="card stat-card"><div className="stat-icon red"><BarChart3 /></div><div><span className="stat-value">{data.totals.rejected}</span><div className="stat-label">반려</div></div></div>
      </div>

      <section className="card"><div className="card-header"><h2><Timer size={17} /> 처리 기간 (제출 → 승인)</h2><Badge>{data.cycle_time.measured}건 기준</Badge></div>
        <div className="card-body">{data.cycle_time.measured ? <div className="grid three">
          <div><span className="subtle">평균</span><div className="stat-value">{data.cycle_time.average_days}일</div></div>
          <div><span className="subtle">중앙값</span><div className="stat-value">{data.cycle_time.median_days}일</div></div>
          <div><span className="subtle">90분위</span><div className="stat-value">{data.cycle_time.p90_days}일</div></div>
        </div> : <Empty title="이 기간에 완료된 심의가 없습니다." description="처리 기간은 제출부터 최종 승인까지를 측정합니다." />}</div></section>

      <div className="grid two">
        <ReportTable title="상태별" rows={data.by_status} columns={[['status', '상태'], ['count', '건수']]} render={{ status: v => <StatusBadge status={String(v)} /> }} />
        <ReportTable title="검토 결과 분포" rows={data.by_result} columns={[['result', '판정'], ['count', '항목 수']]} render={{ result: v => <>{resultLabel[String(v)] || String(v)}</> }} />
      </div>
      <ReportTable title="부서별 현황" rows={data.by_department} columns={[['department', '부서'], ['created', '신규'], ['completed', '완료'], ['average_days', '평균 처리일']]} />
      <ReportTable title="반복 미흡·부적합 항목" rows={data.recurring_findings} columns={[['item_code', '항목코드'], ['title', '보안요건'], ['category', '분류'], ['count', '발생 건수']]} empty="이 기간에 미흡·부적합 판정이 없습니다." />
      <ReportTable title="진행 중 심의 경과" rows={data.aging} columns={[['bucket', '최근 변경 이후'], ['count', '건수']]} empty="진행 중인 심의가 없습니다." />
    </>}
  </div>
}

function ReportTable({ title, rows, columns, render, empty }: { title: string; rows: Row[]; columns: [string, string][]; render?: Record<string, (v: unknown) => React.ReactNode>; empty?: string }) {
  return <section className="card"><div className="card-header"><h2>{title}</h2><Badge>{rows.length}</Badge></div>
    {rows.length ? <div className="table-wrap"><table><caption className="sr-only">{title}</caption>
      <thead><tr>{columns.map(([key, label]) => <th key={key} scope="col">{label}</th>)}</tr></thead>
      <tbody>{rows.map((row, i) => <tr key={i}>{columns.map(([key]) => <td key={key}>{render?.[key] ? render[key](row[key]) : String(row[key] ?? '-')}</td>)}</tr>)}</tbody>
    </table></div> : <Empty title={empty || '집계할 데이터가 없습니다.'} />}
  </section>
}
