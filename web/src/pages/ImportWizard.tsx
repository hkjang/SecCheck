import { ChangeEvent, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Check, FileSpreadsheet, Upload } from 'lucide-react'
import { errorMessage, upload } from '../lib/api'
import { Badge, Button, Empty, Field, useToast } from '../components/ui'

type Mapping = { index: number; header: string; field: string }
type Sheet = { name: string; rows: number; header_row: number; mapping: Mapping[]; columns: Mapping[]; preview: string[][] }
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
      const selected = out.sheets.find(x => x.mapping.length >= 2) || out.sheets[0]
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
    {!preview ? <section className="card"><div className="card-body" style={{ maxWidth: 680, margin: '0 auto', padding: 45 }}><div className="empty"><FileSpreadsheet size={40} /><h3>기존 체크리스트 Excel</h3><p className="subtle">.xlsx 파일만 지원하며 서버에는 원본 파일을 영구 저장하지 않습니다.</p><input type="file" accept=".xlsx" className="input" onChange={(e: ChangeEvent<HTMLInputElement>) => setFile(e.target.files?.[0])} />{file && <p><Badge tone="blue">{file.name}</Badge></p>}<Button variant="primary" disabled={!file || busy} onClick={inspect}><Upload size={14} /> {busy ? '분석 중…' : '파일 분석'}</Button></div></div></section> : <div className="grid two">
      <section className="card"><div className="card-header"><h2>Sheet와 컬럼 매핑</h2></div><div className="card-body"><Field label="Sheet"><select className="select" value={sheet} onChange={e => { const selected = e.target.value; setSheet(selected); setForm(v => ({ ...v, name: selected.replace(/^\(참고\)/, ''), category: inferCategory(selected), version: versionFrom(selected) })) }}>{preview.sheets.map(s => <option key={s.name} value={s.name}>{s.name} ({s.rows}행)</option>)}</select></Field>{current && <><p className="subtle">인식된 헤더 행: {current.header_row}</p>{current.columns.length ? current.columns.map(column => <div className="toggle-row" key={column.index}><span>{column.header || `열 ${column.index + 1}`}</span><select className="select" style={{ width: 180 }} value={column.field} onChange={e => mapColumn(column.index, e.target.value)}>{mappingFields.map(field => <option key={field} value={field}>{field || '가져오지 않음'}</option>)}</select></div>) : <Empty title="헤더 컬럼이 없습니다." />}</>}</div></section>
      <section className="card"><div className="card-header"><h2>생성 설정</h2></div><div className="card-body"><div className="form-grid"><Field label="템플릿 이름" required className="span-2"><input className="input" value={form.name} onChange={e => setForm(v => ({ ...v, name: e.target.value }))} /></Field><Field label="분류"><select className="select" value={form.category} onChange={e => setForm(v => ({ ...v, category: e.target.value }))}><option>DEVELOPMENT</option><option>PRIVACY</option><option>CLOUD</option><option>DOCKER</option><option>KUBERNETES</option></select></Field><Field label="버전"><input className="input" value={form.version} onChange={e => setForm(v => ({ ...v, version: e.target.value }))} /></Field><label className="span-2"><input type="checkbox" checked={form.publish} onChange={e => setForm(v => ({ ...v, publish: e.target.checked }))} /> 검증 후 바로 게시 (게시 버전은 수정할 수 없음)</label></div><div style={{ marginTop: 18, display: 'flex', justifyContent: 'flex-end', gap: 8 }}><Button onClick={() => setPreview(undefined)}>다시 선택</Button><Button variant="primary" disabled={!form.name || !current?.mapping.length || busy} onClick={run}>{busy ? '가져오는 중…' : '템플릿 생성'}</Button></div></div></section>
      {current && <section className="card" style={{ gridColumn: '1 / -1' }}><div className="card-header"><h2>데이터 미리보기</h2><Badge>{current.preview.length}행</Badge></div><div className="table-wrap"><table><tbody>{current.preview.map((row, i) => <tr key={i}>{row.map((cell, j) => <td key={j}>{cell}</td>)}</tr>)}</tbody></table></div></section>}
    </div>}
  </div>
}

function inferCategory(name: string) { const value = name.toLowerCase(); return value.includes('개인') || value.includes('신용') ? 'PRIVACY' : value.includes('클라우드') ? 'CLOUD' : value.includes('docker') ? 'DOCKER' : value.includes('kubernetes') ? 'KUBERNETES' : 'DEVELOPMENT' }
function versionFrom(name: string) { return name.match(/v\d+(?:\.\d+)?/i)?.[0].toUpperCase() || 'V1.0' }
