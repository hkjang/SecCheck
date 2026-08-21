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
  approver_name?: string
  final_result?: string
  final_opinion?: string
  progress?: { total: number; answered: number; evidence: number }
  [key: string]: unknown
}

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
}

export type TemplateVersion = {
  id: string
  version: string
  status: 'DRAFT' | 'PUBLISHED' | 'RETIRED'
  change_note: string
  published_at?: string
  items?: Record<string, unknown>[]
}

export type AuthValue = {
  user: User
  version: string
  refresh: () => Promise<void>
  logout: () => Promise<void>
}
