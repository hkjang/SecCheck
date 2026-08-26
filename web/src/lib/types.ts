export type User = {
  id: string
  username: string
  display_name: string
  email: string
  department: string
  auth_source: string
  active: boolean
  roles: string[]
  locked_until?: string | null
  failed_login_count?: number
  totp_enabled?: boolean
  must_change_password?: boolean
  last_login_at?: string | null
  created_at?: string
}

export type DirectoryUser = Pick<User, 'id' | 'username' | 'display_name' | 'department'>

export type Review = {
  id: string
  review_number: string
  service_name: string
  description?: string
  service_type: string
  change_type: string
  department: string
  status: string
  planned_open_date?: string
  requester_id: string
  reviewer_id?: string
  approver_id?: string
  requester_name?: string
  reviewer_name?: string
  reviewer_can_act?: boolean
  completion_blockers?: { unreviewed_items: number; unverified_changes: number; stale_verdicts: number }
  can_edit?: boolean
  can_review?: boolean
  can_approve?: boolean
  approver_can_act?: boolean
  approver_name?: string
  final_result?: string
  final_opinion?: string
  progress?: { total: number; answered: number; evidence: number }
  open_change_requests?: number
  overdue_change_requests?: number
  [key: string]: unknown
}

export type Page<T> = { items: T[]; total: number; limit: number; offset: number; has_more: boolean }

export type QueueEntry = { id: string; review_number: string; service_name: string; status: string; planned_open_date?: string; updated_at: string; action: string }

export type DueChange = { id: string; review_request_id: string; review_number: string; service_name: string; item_id?: string; item_code: string; title: string; due_date: string; status: string; overdue: boolean }

export type SessionInfo = { id: string; source_ip: string; user_agent: string; created_at: string; last_seen_at: string; expires_at: string; current: boolean }

export type AccountSecurity = { totp_enabled: boolean; totp_enrolled_at?: string; totp_required: boolean; active_sessions: number; auth_source: string }

export type ChecklistItem = {
  id: string
  template_name: string
  template_version: string
  item_code: string
  section: string
  category: string
  title: string
  question: string
  guide: string
  legal_basis: string
  example: string
  severity: string
  required: boolean
  answer_type: string
  evidence_required: boolean
  options: unknown[]
  sort_order: number
  response: Record<string, unknown>
  review_result: Record<string, unknown>
  evidences: Evidence[]
  change_requests: ChangeRequest[]
	comments: { id: string; author_name: string; body: string; created_at: string }[]
  stale_verdict?: boolean
  flags?: { missing_answer: boolean; missing_evidence: boolean; open_change: boolean; stale_verdict: boolean; carried: boolean; commented: boolean; result: string }
}

export type Evidence = {
  id: string
  original_filename: string
  mime_type: string
  size_bytes: number
  sha256: string
  scan_status: string
  current_version: number
  description: string
  scan_detail?: string
}

export type ChangeRequest = {
  id: string
  reason: string
  answer: string
  status: 'OPEN' | 'DONE' | 'VERIFIED'
  due_date?: string
  assignee_id?: string
}

export type Template = {
  id: string
  name: string
  category: string
  description: string
  active: boolean
  versions: TemplateVersion[]
  published_version?: string
  published_items?: number
  broken_rules?: number
}

export type TemplateVersion = {
  id: string
  version: string
  status: 'DRAFT' | 'PUBLISHED' | 'RETIRED'
  change_note: string
  published_at?: string
  items?: Record<string, unknown>[]
}

export type UploadRules = { max_size_mb: number; allowed_extensions: string[] }
export type TextLimits = { long_text: number; short_text: number }

export type AuthValue = {
  user: User
  version: string
  upload?: UploadRules
  limits?: TextLimits
  idleTimeoutMinutes?: number
  passwordChangeRequired?: boolean
  refresh: () => Promise<void>
  logout: () => Promise<void>
  enrolling?: boolean
}
