import { useEffect, useState } from 'react'
import { KeyRound, RefreshCw } from 'lucide-react'
import { errorMessage, get, post } from '../lib/api'
import { Badge, Button, Empty, LoadFailed, Loading, formatDate, useToast } from '../components/ui'

type Key = {
  id: string; name: string; prefix: string; scopes: string[]
  expires_at?: string | null; last_used_at?: string | null; revoked_at?: string | null; created_at: string
  user_id: string; username: string; display_name: string; department: string; owner_active: boolean; usable: boolean
}

// An access review starts by asking which non-human credentials exist. Keys
// used to be visible only to the person who issued them, so nobody could
// answer that question for the installation as a whole.
export default function AdminKeysPage() {
  const toast = useToast()
  const [page, setPage] = useState<{ items: Key[]; usable: number; has_more: boolean }>()
  const [only, setOnly] = useState('ACTIVE')
  const [failed, setFailed] = useState<unknown>()
  const load = () => { setFailed(undefined); return get<{ items: Key[]; usable: number; has_more: boolean }>(`/api/v1/admin/api-keys?limit=200&only=${only}`).then(setPage) }
  useEffect(() => { load().catch(setFailed) }, [only])
  const revoke = async (key: Key) => {
    if (!confirm(`${key.display_name}님의 API 키 ${key.name}(${key.prefix}…)를 폐기할까요?\n이 키를 쓰는 연동은 즉시 중단되고, 소유자에게 알림이 갑니다.`)) return
    try { await post(`/api/v1/admin/api-keys/${key.id}/revoke`); toast.push('API 키를 폐기했습니다.'); await load() }
    catch (e) { toast.push(errorMessage(e), 'error') }
  }
  if (failed) return <LoadFailed error={failed} onRetry={() => load().catch(setFailed)} />
  if (!page) return <Loading />
  return <div className="page">
    <div className="page-header"><div><h1 className="page-title">API 키</h1><p className="page-description">설치 전체의 기계 자격증명과 소유자, 마지막 사용 시각입니다. 계정을 비활성화하면 그 계정의 키도 즉시 통하지 않습니다.</p></div>
      <div className="header-actions"><Badge tone={page.usable ? 'blue' : ''}>사용 가능 {page.usable}개</Badge><Button onClick={() => load().catch(setFailed)}><RefreshCw size={14} /> 새로고침</Button></div></div>
    <div className="toolbar"><select className="select" aria-label="표시 범위" value={only} onChange={e => setOnly(e.target.value)}><option value="ACTIVE">사용 가능한 키</option><option value="">폐기·만료 포함 전체</option></select><span className="subtle">{page.items.length}개 표시</span></div>
    <div className="card">{page.items.length ? <div className="table-wrap"><table><caption className="sr-only">API 키 목록</caption>
      <thead><tr><th scope="col">소유자</th><th scope="col">키</th><th scope="col">범위</th><th scope="col">마지막 사용</th><th scope="col">만료</th><th scope="col">상태</th><th scope="col"><span className="sr-only">작업</span></th></tr></thead>
      <tbody>{page.items.map(k => <tr key={k.id}>
        <td><strong>{k.display_name}</strong><div className="subtle">{k.username}{k.department ? ` · ${k.department}` : ''}</div></td>
        <td>{k.name}<div className="subtle"><code>{k.prefix}…</code></div></td>
        <td>{(k.scopes || []).map(scope => <Badge key={scope} tone={scope === 'read:write' ? 'amber' : ''}>{scope}</Badge>)}</td>
        <td>{k.last_used_at ? formatDate(k.last_used_at, true) : <span className="subtle">사용된 적 없음</span>}</td>
        <td>{k.expires_at ? formatDate(k.expires_at) : <span className="subtle">무기한</span>}</td>
        <td>{k.revoked_at ? <Badge tone="red">폐기됨</Badge> : !k.owner_active ? <Badge tone="red">계정 비활성</Badge> : k.usable ? <Badge tone="green">사용 가능</Badge> : <Badge tone="amber">만료</Badge>}</td>
        <td>{k.revoked_at ? null : <Button small variant="danger" onClick={() => revoke(k)}><KeyRound size={13} /> 폐기</Button>}</td>
      </tr>)}</tbody></table></div> : <Empty title={only === 'ACTIVE' ? '사용 가능한 API 키가 없습니다.' : '발급된 API 키가 없습니다.'} description="개인 키는 프로필 > 개인 키 관리에서 발급합니다." />}
      {page.has_more && <div className="card-body"><p className="subtle">최근 200개만 표시합니다.</p></div>}</div>
  </div>
}
