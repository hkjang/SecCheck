import { PropsWithChildren, ReactNode, createContext, useCallback, useContext, useEffect, useState } from 'react'
import { AlertCircle, Inbox } from 'lucide-react'

export function Button({ children, variant = '', small, ...props }: PropsWithChildren<React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'danger' | 'success' | 'ghost' | ''; small?: boolean }>) {
  return <button className={`button ${variant} ${small ? 'small' : ''}`} {...props}>{children}</button>
}

export function Badge({ children, tone = '' }: PropsWithChildren<{ tone?: 'blue' | 'green' | 'amber' | 'red' | 'purple' | '' }>) {
  return <span className={`badge ${tone}`}>{children}</span>
}

export function Field({ label, required, help, error, children, className = '' }: PropsWithChildren<{ label: string; required?: boolean; help?: string; error?: string; className?: string }>) {
  return <div className={`field ${className}`}><label>{label}{required && <span className="required">*</span>}</label>{children}{help && <span className="field-help">{help}</span>}{error && <span className="field-error">{error}</span>}</div>
}

export function Toggle({ value, onChange, label }: { value: boolean; onChange: (value: boolean) => void; label: string }) {
  return <div className="toggle-row"><span>{label}</span><button type="button" aria-label={label} aria-pressed={value} className={`switch ${value ? 'on' : ''}`} onClick={() => onChange(!value)} /></div>
}

export function Empty({ title = '표시할 항목이 없습니다.', description }: { title?: string; description?: string }) {
  return <div className="empty"><Inbox /><div>{title}</div>{description && <p className="subtle">{description}</p>}</div>
}

export function Loading() { return <div className="loading"><div className="spinner" aria-label="불러오는 중" /></div> }

export function Modal({ title, children, footer, onClose, className = '' }: PropsWithChildren<{ title?: string; footer?: ReactNode; onClose: () => void; className?: string }>) {
  useEffect(() => { const close = (e: KeyboardEvent) => e.key === 'Escape' && onClose(); window.addEventListener('keydown', close); return () => window.removeEventListener('keydown', close) }, [onClose])
  return <div className="modal-backdrop" onMouseDown={e => e.target === e.currentTarget && onClose()}><div className={`modal ${className}`}>{title && <div className="modal-header"><strong>{title}</strong><Button variant="ghost" onClick={onClose}>닫기</Button></div>}<div className="modal-body">{children}</div>{footer && <div className="modal-footer">{footer}</div>}</div></div>
}

type ToastValue = { push: (message: string, kind?: 'normal' | 'error') => void }
const ToastContext = createContext<ToastValue>({ push: () => undefined })
export function ToastProvider({ children }: PropsWithChildren) {
  const [items, setItems] = useState<{ id: number; message: string; kind: string }[]>([])
  const push = useCallback((message: string, kind: 'normal' | 'error' = 'normal') => { const id = Date.now(); setItems(v => [...v, { id, message, kind }]); window.setTimeout(() => setItems(v => v.filter(x => x.id !== id)), 4200) }, [])
  return <ToastContext.Provider value={{ push }}>{children}<div className="toast-stack">{items.map(item => <div key={item.id} className={`toast ${item.kind === 'error' ? 'error' : ''}`}>{item.kind === 'error' && <AlertCircle size={15} />} {item.message}</div>)}</div></ToastContext.Provider>
}
export const useToast = () => useContext(ToastContext)

export const statusLabel: Record<string, string> = {
  DRAFT: '작성 중', SUBMITTED: '제출 완료', REVIEWING: '검토 중', CHANGE_REQUESTED: '보완 요청', RESUBMITTED: '재제출', APPROVAL_PENDING: '승인 대기', APPROVED: '심의 완료', REJECTED: '반려', CLOSED: '종료', CANCELLED: '취소', PUBLISHED: '게시', RETIRED: '사용 중지'
}
export function StatusBadge({ status }: { status: string }) {
  const tone = ['APPROVED', 'PUBLISHED', 'CLOSED'].includes(status) ? 'green' : ['REJECTED', 'CANCELLED'].includes(status) ? 'red' : ['CHANGE_REQUESTED', 'APPROVAL_PENDING'].includes(status) ? 'amber' : ['REVIEWING', 'SUBMITTED', 'RESUBMITTED'].includes(status) ? 'blue' : ''
  return <Badge tone={tone}>{statusLabel[status] || status}</Badge>
}

export function formatDate(value: unknown, withTime = false) {
  if (!value) return '-'
  const date = new Date(String(value))
  if (Number.isNaN(date.getTime())) return String(value)
  return new Intl.DateTimeFormat('ko-KR', { year: 'numeric', month: '2-digit', day: '2-digit', ...(withTime ? { hour: '2-digit', minute: '2-digit' } : {}) }).format(date)
}

export function formatBytes(value: number) {
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`
  return `${(value / 1024 / 1024).toFixed(1)} MB`
}
