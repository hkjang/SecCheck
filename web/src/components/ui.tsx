import { PropsWithChildren, ReactElement, ReactNode, cloneElement, createContext, isValidElement, useCallback, useContext, useEffect, useId, useRef, useState } from 'react'
import { AlertCircle, Inbox, RefreshCw } from 'lucide-react'
import { download, errorMessage } from '../lib/api'

export function Button({ children, variant = '', small, ...props }: PropsWithChildren<React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'danger' | 'success' | 'ghost' | ''; small?: boolean }>) {
  return <button className={`button ${variant} ${small ? 'small' : ''}`} {...props}>{children}</button>
}

export function Badge({ children, tone = '' }: PropsWithChildren<{ tone?: 'blue' | 'green' | 'amber' | 'red' | 'purple' | '' }>) {
  return <span className={`badge ${tone}`}>{children}</span>
}

// The label used to sit beside the control rather than being attached to it,
// so a screen reader announced every field in the product as an unnamed text
// box, clicking the label did nothing, and the help and error lines were read
// only if somebody navigated to them separately. One control gets the id; a
// field holding several is left as it was, since there is nothing to point at.
export function Field({ label, required, help, error, children, className = '' }: PropsWithChildren<{ label: string; required?: boolean; help?: string; error?: string; className?: string }>) {
  const generated = useId()
  const single = isValidElement(children) ? (children as ReactElement<Record<string, unknown>>) : null
  const id = String(single?.props?.id || generated)
  const describedBy = [help ? `${id}-help` : '', error ? `${id}-error` : ''].filter(Boolean).join(' ')
  const control = single
    ? cloneElement(single, {
      id,
      ...(describedBy ? { 'aria-describedby': describedBy } : {}),
      ...(error ? { 'aria-invalid': true } : {}),
      ...(required ? { 'aria-required': true } : {}),
    })
    : children
  return <div className={`field ${className}`}>
    {single ? <label htmlFor={id}>{label}{required && <span className="required">*</span>}</label> : <label>{label}{required && <span className="required">*</span>}</label>}
    {control}
    {help && <span className="field-help" id={`${id}-help`}>{help}</span>}
    {error && <span className="field-error" id={`${id}-error`}>{error}</span>}
  </div>
}

export function Toggle({ value, onChange, label }: { value: boolean; onChange: (value: boolean) => void; label: string }) {
  return <div className="toggle-row"><span>{label}</span><button type="button" aria-label={label} aria-pressed={value} className={`switch ${value ? 'on' : ''}`} onClick={() => onChange(!value)} /></div>
}

export function Empty({ title = '표시할 항목이 없습니다.', description }: { title?: string; description?: string }) {
  return <div className="empty"><Inbox /><div>{title}</div>{description && <p className="subtle">{description}</p>}</div>
}

export function Loading() { return <div className="loading"><div className="spinner" aria-label="불러오는 중" /></div> }

// Saving a file is a request like any other, so its failure belongs in a
// toast next to the button, not in a tab that navigated away to JSON.
export function useDownload() {
  const toast = useToast()
  return async (path: string) => {
    try {
      const { cappedAt } = await download(path)
      if (cappedAt) toast.push(`가장 최근 ${cappedAt.toLocaleString()}건까지만 내보냈습니다. 기간이나 조건을 좁혀 다시 내보내세요.`, 'error')
    } catch (error) { toast.push(errorMessage(error), 'error') }
  }
}

// Pages gate their whole body on `!data`, so a first load that fails used to
// leave the spinner turning for good -- at best with a toast that vanished
// seconds later. This says what went wrong and stays on screen.
export function LoadFailed({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return <div className="empty" role="alert"><AlertCircle /><div>화면을 불러오지 못했습니다.</div><p className="subtle">{errorMessage(error)}</p>
    {onRetry && <Button onClick={onRetry}><RefreshCw size={14} /> 다시 시도</Button>}</div>
}

// A dialog that does not take focus is a dialog a keyboard user cannot reach:
// the page behind it keeps the focus ring, Tab walks the page rather than the
// form on top of it, and closing leaves focus nowhere. Assistive technology
// was not told it was a dialog either.
export function Modal({ title, children, footer, onClose, className = '' }: PropsWithChildren<{ title?: string; footer?: ReactNode; onClose: () => void; className?: string }>) {
  const titleID = useId()
  const dialog = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null
    const focusable = () => Array.from(dialog.current?.querySelectorAll<HTMLElement>('a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])') || [])
    const first = focusable()[0]
    ;(first || dialog.current)?.focus()
    const key = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { onClose(); return }
      if (e.key !== 'Tab') return
      const items = focusable()
      if (!items.length) return
      const edge = e.shiftKey ? items[0] : items[items.length - 1]
      if (document.activeElement === edge || !dialog.current?.contains(document.activeElement)) {
        e.preventDefault()
        ;(e.shiftKey ? items[items.length - 1] : items[0]).focus()
      }
    }
    window.addEventListener('keydown', key)
    return () => { window.removeEventListener('keydown', key); opener?.focus?.() }
  }, [onClose])
  return <div className="modal-backdrop" onMouseDown={e => e.target === e.currentTarget && onClose()}>
    <div ref={dialog} className={`modal ${className}`} role="dialog" aria-modal="true" tabIndex={-1} {...(title ? { 'aria-labelledby': titleID } : { 'aria-label': '대화 상자' })}>
      {title && <div className="modal-header"><strong id={titleID}>{title}</strong><Button variant="ghost" onClick={onClose}>닫기</Button></div>}
      <div className="modal-body">{children}</div>
      {footer && <div className="modal-footer">{footer}</div>}
    </div>
  </div>
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

// The service decides which zone dates are read in, so a reviewer in another
// region sees the same timestamp as the audit log and the exported report
// rather than one shifted by their laptop's setting.
let displayTimezone = ''
export function setDisplayTimezone(zone: string) { displayTimezone = zone }

export function formatDate(value: unknown, withTime = false) {
  if (!value) return '-'
  const date = new Date(String(value))
  if (Number.isNaN(date.getTime())) return String(value)
  const options: Intl.DateTimeFormatOptions = { year: 'numeric', month: '2-digit', day: '2-digit', ...(withTime ? { hour: '2-digit', minute: '2-digit' } : {}) }
  if (displayTimezone) options.timeZone = displayTimezone
  try {
    return new Intl.DateTimeFormat('ko-KR', options).format(date)
  } catch {
    // An unusable zone name must not blank out every date on the page.
    delete options.timeZone
    return new Intl.DateTimeFormat('ko-KR', options).format(date)
  }
}

export function formatBytes(value: number) {
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`
  return `${(value / 1024 / 1024).toFixed(1)} MB`
}
