import { ChangeEvent, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertTriangle, Check, FileSpreadsheet, Upload } from 'lucide-react'
import { errorMessage, upload } from '../lib/api'
import { Badge, Button, Empty, Field, useToast } from '../components/ui'

type Mapping = { index: number; header: string; field: string }
type Report = { parsed: number; skipped_rows: number; generated_codes: number; duplicate_codes: string[]; missing_fields: string[]; shortened_fields: number }
type ParsedItem = { item_code: string; section: string; title: string; question: string; severity: string }
type Sheet = { name: string; rows: number; header_row: number; mapping: Mapping[]; columns: Mapping[]; preview: string[][]; report: Report; items: ParsedItem[] }
const fieldLabel: Record<string, string> = { item_code: '항목코드', title: '보안요건', question: '점검항목', guide: '점검 가이드', severity: '중요도', section: '구분', legal_basis: '관련 근거', example: '현황 및 증적' }
const mappingFields = ['', 'section', 'item_code', 'title', 'question', 'guide', 'legal_basis', 'example', 'severity']

export default function ImportWizard() {
  const navigate = useNavigate()
  const toast = useToast()
  const [file, setFile] = useState<File>()
  const [preview, setPreview] = useState<{ filename: string; sheets: Sheet[] }>()
  const [sheet, setSheet] = useState('')
  const [form, setForm] = useState({ name: '', category: 'DEVELOPMENT', version: 'V1.0', publish: false })
  const [busy, setBusy] = useState(false)
  const current = preview?.sheets.find(x => x.name === sheet)
  const step = !preview ? 1 : 2

  const inspect = async () => {
    if (!file) return
    setBusy(true)
    const data = new FormData()
    data.append('file', file)
    try {
      const out = await upload<{ filename: string; sheets: Sheet[] }>('/api/v1/templates/import/preview', data)
      setPreview(out)
      const selected = [...out.sheets].sort((a, b) => (b.report?.parsed || 0) - (a.report?.parsed || 0))[0]
      if (selected) {
        setSheet(selected.name)
        setForm(v => ({ ...v, name: selected.name.replace(/^\(참고\)/, ''), category: inferCategory(selected.name), version: versionFrom(selected.name) }))
      }
    } catch (e) {
      toast.push(errorMessage(e), 'error')
    } finally {
      setBusy(false)
    }
  }

  const mapColumn = (index: number, field: string) => setPreview(value => value ? {
    ...value,
    sheets: value.sheets.map(s => s.name === sheet ? {
      ...s,
      columns: s.columns.map(c => c.index === index ? { ...c, field } : c),
      mapping: s.columns.map(c => c.index === index ? { ...c, field } : c).filter(c => c.field),
    } : s),
  } : value)

  const run = async () => {
    if (!file || !sheet || !current) return
    setBusy(true)
    const data = new FormData()
    data.append('file', file)
    data.append('sheet', sheet)
    data.append('mapping', JSON.stringify(current.columns.filter(x => x.field)))
    Object.entries(form).forEach(([key, value]) => data.append(key, String(value)))
    try {
      const out = await upload<{ id: string; items: number }>('/api/v1/templates/import', data)
      toast.push(`${out.items}개 항목을 가져왔습니다.`)
      navigate(`/templates/${out.id}`)
    } catch (e) {
      toast.push(errorMessage(e), 'error')
    } finally {
      setBusy(false)
    }
  }

  return <div className="page">
    <div className="page-header"><div><h1 className="page-title">Excel Import Wizard</h1><p className="page-description">Sheet 선택, 헤더 인식, 직접 수정 가능한 컬럼 매핑과 미리보기를 거쳐 템플릿을 생성합니다.</p></div></div>
    <div className="stepper"><div className={`step ${step === 1 ? 'active' : 'done'}`}><span>{step > 1 ? <Check size={14} /> : '1'}</span>Excel 업로드</div><div className={`step ${step === 2 ? 'active' : ''}`}><span>2</span>Sheet · 매핑 확인</div><div className="step"><span>3</span>템플릿 생성</div></div>
    {!preview ? <section className="card"><div className="card-body" data-sx="sx-039"><div className="empty"><FileSpreadsheet size={40} /><h3>기존 체크리스트 Excel</h3><p className="subtle">.xlsx 파일만 지원하며 서버에는 원본 파일을 영구 저장하지 않습니다.</p><input type="file" accept=".xlsx" className="input" onChange={(e: ChangeEvent<HTMLInputElement>) => setFile(e.target.files?.[0])} />{file && <p><Badge tone="blue">{file.name}</Badge></p>}<Button variant="primary" disabled={!file || busy} onClick={inspect}><Upload size={14} /> {busy ? '분석 중…' : '파일 분석'}</Button></div></div></section> : <div className="grid two">
      <section className="card"><div className="card-header"><h2>Sheet와 컬럼 매핑</h2></div><div className="card-body"><Field label="Sheet"><select className="select" value={sheet} onChange={e => { const selected = e.target.value; setSheet(selected); setForm(v => ({ ...v, name: selected.replace(/^\(참고\)/, ''), category: inferCategory(selected), version: versionFrom(selected) })) }}>{preview.sheets.map(s => <option key={s.name} value={s.name}>{s.name} ({s.rows}행)</option>)}</select></Field>{current && <><p className="subtle">인식된 헤더 행: {current.header_row}</p>{current.columns.length ? current.columns.map(column => <div className="toggle-row" key={column.index}><span>{column.header || `열 ${column.index + 1}`}</span><select className="select" data-sx="sx-052" value={column.field} onChange={e => mapColumn(column.index, e.target.value)}>{mappingFields.map(field => <option key={field} value={field}>{field || '가져오지 않음'}</option>)}</select></div>) : <Empty title="헤더 컬럼이 없습니다." />}</>}</div></section>
      <section className="card"><div className="card-header"><h2>생성 설정</h2></div><div className="card-body"><div className="form-grid"><Field label="템플릿 이름" required className="span-2"><input className="input" value={form.name} onChange={e => setForm(v => ({ ...v, name: e.target.value }))} /></Field><Field label="분류"><select className="select" value={form.category} onChange={e => setForm(v => ({ ...v, category: e.target.value }))}><option>DEVELOPMENT</option><option>PRIVACY</option><option>CLOUD</option><option>DOCKER</option><option>KUBERNETES</option></select></Field><Field label="버전"><input className="input" value={form.version} onChange={e => setForm(v => ({ ...v, version: e.target.value }))} /></Field><label className="span-2"><input type="checkbox" checked={form.publish} onChange={e => setForm(v => ({ ...v, publish: e.target.checked }))} /> 검증 후 바로 게시 (게시 버전은 수정할 수 없음)</label></div><div data-sx="sx-032"><Button onClick={() => setPreview(undefined)}>다시 선택</Button><Button variant="primary" disabled={!form.name || !current?.mapping.length || busy} onClick={run}>{busy ? '가져오는 중…' : '템플릿 생성'}</Button></div></div></section>
      {current && <section className="card" data-sx="sx-021"><div className="card-header"><h2>가져오기 결과 미리보기</h2><Badge tone={current.report.parsed ? 'green' : 'red'}>{current.report.parsed}개 항목</Badge></div>
        <div className="card-body">
          {current.report.parsed === 0 && <div className="guide-block">이 Sheet에서 가져올 항목을 찾지 못했습니다. 헤더 행과 컬럼 매핑을 확인하거나 다른 Sheet를 선택하세요.</div>}
          {(current.report.skipped_rows > 0 || current.report.generated_codes > 0 || current.report.duplicate_codes.length > 0 || current.report.missing_fields.length > 0 || current.report.shortened_fields > 0) &&
            <div className="guide-block"><strong><AlertTriangle size={14} /> 가져오기 시 이렇게 처리됩니다</strong>
              <ul>
                {current.report.skipped_rows > 0 && <li>{current.report.skipped_rows}개 행은 보안요건과 점검항목이 모두 비어 있어 건너뜁니다.</li>}
                {current.report.shortened_fields > 0 && <li>{current.report.shortened_fields}개 항목의 긴 항목이 최대 길이로 잘립니다(제목 300자, 안내·질문·예시 4,000자, 근거 2,000자).</li>}
                {current.report.generated_codes > 0 && <li>{current.report.generated_codes}개 항목은 항목코드가 없어 <code>{form.category}-001</code> 형식으로 자동 부여됩니다.</li>}
                {current.report.duplicate_codes.length > 0 && <li>중복 항목코드 {current.report.duplicate_codes.length}개에 <code>-DUP2</code> 접미사가 붙습니다: {current.report.duplicate_codes.slice(0, 5).join(', ')}{current.report.duplicate_codes.length > 5 ? ' 외' : ''}</li>}
                {current.report.missing_fields.length > 0 && <li>매핑되지 않은 컬럼: {current.report.missing_fields.map(f => fieldLabel[f] || f).join(', ')}. 필요하면 왼쪽에서 지정하세요.</li>}
              </ul></div>}
        </div>
        {current.items.length > 0 && <div className="table-wrap"><table><caption className="sr-only">생성될 체크리스트 항목 미리보기</caption><thead><tr><th scope="col">항목코드</th><th scope="col">구분</th><th scope="col">보안요건</th><th scope="col">점검항목</th><th scope="col">중요도</th></tr></thead>
          <tbody>{current.items.map((item, i) => <tr key={i}><td><code>{item.item_code}</code></td><td>{item.section || '-'}</td><td><strong>{item.title}</strong></td><td className="subtle">{item.question}</td><td>{item.severity}</td></tr>)}</tbody></table></div>}
        <div className="card-body"><p className="subtle">전체 {current.report.parsed}개 중 상위 {current.items.length}개를 표시했습니다. 잘못 가져왔다면 생성 직후 템플릿 화면에서 삭제할 수 있습니다 (게시 전, 심의에 사용되기 전까지).</p></div>
      </section>}
    </div>}
  </div>
}

function inferCategory(name: string) { const value = name.toLowerCase(); return value.includes('개인') || value.includes('신용') ? 'PRIVACY' : value.includes('클라우드') ? 'CLOUD' : value.includes('docker') ? 'DOCKER' : value.includes('kubernetes') ? 'KUBERNETES' : 'DEVELOPMENT' }
function versionFrom(name: string) { return name.match(/v\d+(?:\.\d+)?/i)?.[0].toUpperCase() || 'V1.0' }
