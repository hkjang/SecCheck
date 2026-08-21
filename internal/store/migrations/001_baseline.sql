CREATE TABLE IF NOT EXISTS schema_migrations (
  version integer PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id text PRIMARY KEY,
  username text NOT NULL UNIQUE,
  display_name text NOT NULL,
  email text NOT NULL DEFAULT '',
  department text NOT NULL DEFAULT '',
  password_hash text NOT NULL DEFAULT '',
  auth_source text NOT NULL DEFAULT 'local',
  active boolean NOT NULL DEFAULT true,
  last_login_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_count integer NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until timestamptz;

CREATE TABLE IF NOT EXISTS roles (
  code text PRIMARY KEY,
  name text NOT NULL,
  description text NOT NULL DEFAULT ''
);
INSERT INTO roles(code,name,description) VALUES
 ('SYSTEM_ADMIN','시스템 관리자','시스템 설정, 사용자 및 역할 관리'),
 ('TEMPLATE_ADMIN','체크리스트 관리자','템플릿 및 버전 관리'),
 ('SECURITY_REVIEWER','보안 담당자','심의 배정, 검토 및 보완요청'),
 ('REQUESTER','심의 요청자','심의 생성 및 제출'),
 ('CONTRIBUTOR','공동 작성자','지정 심의 작성'),
 ('APPROVER','승인자','최종 승인 및 반려'),
 ('AUDITOR','감사자','읽기 전용 및 감사로그 조회')
ON CONFLICT (code) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description;

CREATE TABLE IF NOT EXISTS user_roles (
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_code text NOT NULL REFERENCES roles(code) ON DELETE CASCADE,
  PRIMARY KEY(user_id, role_code)
);

CREATE TABLE IF NOT EXISTS sessions (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash bytea NOT NULL UNIQUE,
  csrf_token text NOT NULL,
  source_ip text NOT NULL DEFAULT '',
  user_agent text NOT NULL DEFAULT '',
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_last_seen ON sessions(last_seen_at);

CREATE TABLE IF NOT EXISTS oidc_states (
  state_hash bytea PRIMARY KEY,
  nonce text NOT NULL,
  code_verifier text NOT NULL,
  return_to text NOT NULL DEFAULT '/',
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_oidc_states_expiry ON oidc_states(expires_at);

CREATE TABLE IF NOT EXISTS settings (
  key text PRIMARY KEY,
  value_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  encrypted_value text NOT NULL DEFAULT '',
  sensitive boolean NOT NULL DEFAULT false,
  updated_by text REFERENCES users(id),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_data_keys (
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  version integer NOT NULL,
  encrypted_key text NOT NULL,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  PRIMARY KEY(user_id, version)
);

CREATE TABLE IF NOT EXISTS api_keys (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name text NOT NULL,
  prefix text NOT NULL,
  secret_hash bytea NOT NULL UNIQUE,
  scopes text[] NOT NULL DEFAULT ARRAY['read']::text[],
  expires_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS security_controls (
  id text PRIMARY KEY,
  code text NOT NULL UNIQUE,
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  owner_id text REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS checklist_templates (
  id text PRIMARY KEY,
  name text NOT NULL,
  category text NOT NULL,
  description text NOT NULL DEFAULT '',
  active boolean NOT NULL DEFAULT true,
  created_by text NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS checklist_versions (
  id text PRIMARY KEY,
  template_id text NOT NULL REFERENCES checklist_templates(id) ON DELETE CASCADE,
  version text NOT NULL,
  status text NOT NULL DEFAULT 'DRAFT' CHECK(status IN ('DRAFT','PUBLISHED','RETIRED')),
  change_note text NOT NULL DEFAULT '',
  source_filename text NOT NULL DEFAULT '',
  created_by text NOT NULL REFERENCES users(id),
  published_by text REFERENCES users(id),
  published_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(template_id, version)
);

CREATE TABLE IF NOT EXISTS checklist_sections (
  id text PRIMARY KEY,
  version_id text NOT NULL REFERENCES checklist_versions(id) ON DELETE CASCADE,
  name text NOT NULL,
  sort_order integer NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS checklist_items (
  id text PRIMARY KEY,
  version_id text NOT NULL REFERENCES checklist_versions(id) ON DELETE CASCADE,
  section_id text REFERENCES checklist_sections(id) ON DELETE SET NULL,
  control_id text REFERENCES security_controls(id) ON DELETE SET NULL,
  item_code text NOT NULL,
  category text NOT NULL,
  title text NOT NULL,
  question text NOT NULL,
  guide text NOT NULL DEFAULT '',
  legal_basis text NOT NULL DEFAULT '',
  example text NOT NULL DEFAULT '',
  severity text NOT NULL DEFAULT 'MEDIUM',
  required boolean NOT NULL DEFAULT true,
  answer_type text NOT NULL DEFAULT 'YNNA',
  evidence_required boolean NOT NULL DEFAULT false,
  applicability_rule jsonb NOT NULL DEFAULT '{}'::jsonb,
  options_json jsonb NOT NULL DEFAULT '[]'::jsonb,
  sort_order integer NOT NULL DEFAULT 0,
  UNIQUE(version_id,item_code)
);

CREATE TABLE IF NOT EXISTS template_changes (
  id text PRIMARY KEY,
  version_id text NOT NULL REFERENCES checklist_versions(id) ON DELETE CASCADE,
  item_code text NOT NULL,
  change_type text NOT NULL,
  before_json jsonb,
  after_json jsonb,
  changed_by text NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS review_requests (
  id text PRIMARY KEY,
  review_number text NOT NULL UNIQUE,
  service_name text NOT NULL,
  description text NOT NULL,
  service_type text NOT NULL,
  change_type text NOT NULL,
  builder_id text NOT NULL REFERENCES users(id),
  developer_id text NOT NULL REFERENCES users(id),
  operator_id text REFERENCES users(id),
  department text NOT NULL,
  requester_id text NOT NULL REFERENCES users(id),
  reviewer_id text REFERENCES users(id),
  approver_id text REFERENCES users(id),
  planned_open_date date,
  exposure text NOT NULL,
  has_admin_page boolean NOT NULL DEFAULT false,
  processes_personal_data boolean NOT NULL DEFAULT false,
  processes_credit_data boolean NOT NULL DEFAULT false,
  external_customer_service boolean NOT NULL DEFAULT false,
  uses_cloud boolean NOT NULL DEFAULT false,
  uses_docker boolean NOT NULL DEFAULT false,
  uses_kubernetes boolean NOT NULL DEFAULT false,
  external_integration boolean NOT NULL DEFAULT false,
  internet_access boolean NOT NULL DEFAULT false,
  business_criticality text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'DRAFT',
  final_opinion text NOT NULL DEFAULT '',
  final_result text NOT NULL DEFAULT '',
  manual_rule_override_reason text NOT NULL DEFAULT '',
  first_submitted_at timestamptz,
  final_submitted_at timestamptz,
  approved_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_review_requests_access ON review_requests(requester_id, reviewer_id, status);
CREATE INDEX IF NOT EXISTS idx_review_requests_search ON review_requests(service_name, review_number);

CREATE TABLE IF NOT EXISTS review_participants (
  review_request_id text NOT NULL REFERENCES review_requests(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  participant_role text NOT NULL DEFAULT 'CONTRIBUTOR',
  PRIMARY KEY(review_request_id,user_id)
);

CREATE TABLE IF NOT EXISTS submissions (
  id text PRIMARY KEY,
  review_request_id text NOT NULL REFERENCES review_requests(id) ON DELETE CASCADE,
  revision integer NOT NULL DEFAULT 1,
  status text NOT NULL DEFAULT 'DRAFT',
  submitted_by text REFERENCES users(id),
  submitted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(review_request_id,revision)
);

CREATE TABLE IF NOT EXISTS rule_overrides (
  id text PRIMARY KEY,
  review_request_id text NOT NULL REFERENCES review_requests(id) ON DELETE CASCADE,
  submission_id text NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
  source_item_id text NOT NULL REFERENCES checklist_items(id),
  action text NOT NULL CHECK(action IN ('INCLUDE','EXCLUDE')),
  reason text NOT NULL,
  changed_by text NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS submission_items (
  id text PRIMARY KEY,
  submission_id text NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
  source_item_id text REFERENCES checklist_items(id) ON DELETE SET NULL,
  template_name text NOT NULL,
  template_version text NOT NULL,
  item_code text NOT NULL,
  section text NOT NULL,
  category text NOT NULL,
  title text NOT NULL,
  question text NOT NULL,
  guide text NOT NULL DEFAULT '',
  legal_basis text NOT NULL DEFAULT '',
  example text NOT NULL DEFAULT '',
  severity text NOT NULL,
  required boolean NOT NULL,
  answer_type text NOT NULL,
  evidence_required boolean NOT NULL,
  options_json jsonb NOT NULL DEFAULT '[]'::jsonb,
  sort_order integer NOT NULL,
  UNIQUE(submission_id,source_item_id)
);

CREATE TABLE IF NOT EXISTS responses (
  id text PRIMARY KEY,
  submission_item_id text NOT NULL UNIQUE REFERENCES submission_items(id) ON DELETE CASCADE,
  answer_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  applicability text NOT NULL DEFAULT '',
  self_assessment text NOT NULL DEFAULT '',
  current_state text NOT NULL DEFAULT '',
  na_reason text NOT NULL DEFAULT '',
  action_plan text NOT NULL DEFAULT '',
  assigned_to text REFERENCES users(id),
  updated_by text NOT NULL REFERENCES users(id),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS evidences (
  id text PRIMARY KEY,
  submission_item_id text NOT NULL REFERENCES submission_items(id) ON DELETE CASCADE,
  original_filename text NOT NULL,
  stored_filename text NOT NULL,
  mime_type text NOT NULL,
  size_bytes bigint NOT NULL,
  sha256 text NOT NULL,
  uploaded_by text NOT NULL REFERENCES users(id),
  key_owner_id text NOT NULL REFERENCES users(id),
  key_version integer NOT NULL,
  description text NOT NULL DEFAULT '',
  scan_status text NOT NULL DEFAULT 'PENDING',
  current_version integer NOT NULL DEFAULT 1,
  deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS evidence_versions (
  id text PRIMARY KEY,
  evidence_id text NOT NULL REFERENCES evidences(id) ON DELETE CASCADE,
  version integer NOT NULL,
  stored_filename text NOT NULL,
  size_bytes bigint NOT NULL,
  sha256 text NOT NULL,
  mime_type text NOT NULL,
  key_owner_id text NOT NULL REFERENCES users(id),
  key_version integer NOT NULL,
  scan_status text NOT NULL DEFAULT 'PENDING',
  uploaded_by text NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(evidence_id,version)
);

CREATE TABLE IF NOT EXISTS review_results (
  id text PRIMARY KEY,
  submission_item_id text NOT NULL UNIQUE REFERENCES submission_items(id) ON DELETE CASCADE,
  reviewer_id text NOT NULL REFERENCES users(id),
  final_applicability text NOT NULL DEFAULT '',
  result text NOT NULL DEFAULT '',
  opinion text NOT NULL DEFAULT '',
  evidence_adequacy text NOT NULL DEFAULT '',
  na_approved boolean,
  follow_up text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS change_requests (
  id text PRIMARY KEY,
  review_request_id text NOT NULL REFERENCES review_requests(id) ON DELETE CASCADE,
  submission_item_id text NOT NULL REFERENCES submission_items(id) ON DELETE CASCADE,
  reason text NOT NULL,
  requester_id text NOT NULL REFERENCES users(id),
  assignee_id text REFERENCES users(id),
  due_date date,
  answer text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','DONE','VERIFIED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS comments (
  id text PRIMARY KEY,
  submission_item_id text NOT NULL REFERENCES submission_items(id) ON DELETE CASCADE,
  author_id text NOT NULL REFERENCES users(id),
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS approvals (
  id text PRIMARY KEY,
  review_request_id text NOT NULL REFERENCES review_requests(id) ON DELETE CASCADE,
  approver_id text NOT NULL REFERENCES users(id),
  decision text NOT NULL,
  comment text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS notifications (
  id text PRIMARY KEY,
  recipient_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  event_type text NOT NULL,
  title text NOT NULL,
  body text NOT NULL,
  channel text NOT NULL DEFAULT 'IN_APP',
  status text NOT NULL DEFAULT 'PENDING',
  read_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  event_id text PRIMARY KEY,
  timestamp timestamptz NOT NULL DEFAULT now(),
  user_id text REFERENCES users(id),
  user_name text NOT NULL DEFAULT '',
  source_ip text NOT NULL DEFAULT '',
  session_id text NOT NULL DEFAULT '',
  event_type text NOT NULL,
  target_type text NOT NULL DEFAULT '',
  target_id text NOT NULL DEFAULT '',
  before_value jsonb,
  after_value jsonb,
  request_id text NOT NULL DEFAULT '',
  result text NOT NULL DEFAULT 'SUCCESS',
  previous_hash text NOT NULL DEFAULT '',
  canonical_payload text NOT NULL DEFAULT '',
  event_hash text NOT NULL
);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS canonical_payload text NOT NULL DEFAULT '';
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS chain_sequence bigint;
WITH numbered AS (
  SELECT event_id,row_number() OVER(ORDER BY timestamp,event_id) AS seq
  FROM audit_logs WHERE chain_sequence IS NULL
) UPDATE audit_logs a SET chain_sequence=n.seq FROM numbered n WHERE a.event_id=n.event_id;
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_chain_sequence ON audit_logs(chain_sequence);
CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(timestamp DESC);

CREATE TABLE IF NOT EXISTS audit_chain_state (
  id smallint PRIMARY KEY CHECK(id=1),
  head_hash text NOT NULL DEFAULT '',
  sequence bigint NOT NULL DEFAULT 0
);
INSERT INTO audit_chain_state(id,head_hash,sequence)
SELECT 1,COALESCE((SELECT event_hash FROM audit_logs ORDER BY chain_sequence DESC LIMIT 1),''),COALESCE((SELECT max(chain_sequence) FROM audit_logs),0)
ON CONFLICT(id) DO NOTHING;

CREATE TABLE IF NOT EXISTS application_logs (
  id bigserial PRIMARY KEY,
  timestamp timestamptz NOT NULL DEFAULT now(),
  level text NOT NULL,
  request_id text NOT NULL DEFAULT '',
  component text NOT NULL DEFAULT 'api',
  message text NOT NULL,
  fields jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_application_logs_time ON application_logs(timestamp DESC);

CREATE TABLE IF NOT EXISTS jobs (
  id text PRIMARY KEY,
  type text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'PENDING',
  attempts integer NOT NULL DEFAULT 0,
  available_at timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_jobs_claim ON jobs(status,available_at,created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_retention ON jobs(status,updated_at);

INSERT INTO settings(key,value_json,sensitive) VALUES
 ('general', '{"service_name":"SecCheck","timezone":"Asia/Seoul","session_minutes":480,"retention_days":1825}'::jsonb, false),
 ('workflow', '{"approval_enabled":false,"require_reviewer_assignment":false}'::jsonb, false),
 ('upload', '{"max_size_mb":25,"allowed_extensions":["pdf","png","jpg","jpeg","xlsx","xls","docx","zip","txt","json"],"clamav_enabled":false,"clamav_address":""}'::jsonb, false),
 ('oidc', '{"enabled":false,"issuer":"","client_id":"","redirect_url":"","scopes":["openid","profile","email"],"username_claim":"preferred_username","default_role":"REQUESTER"}'::jsonb, false),
 ('notification', '{"email_enabled":false,"smtp_host":"","smtp_port":25,"smtp_username":"","smtp_tls_mode":"starttls","from":""}'::jsonb, false),
 ('security', '{"cookie_secure":false,"cors_origins":[],"rate_limit_per_minute":120,"inactive_admin_lock_days":90,"login_rate_limit_per_minute":30,"max_login_failures":5,"lockout_minutes":15,"idle_timeout_minutes":0,"trusted_proxies":[]}'::jsonb, false)
ON CONFLICT (key) DO NOTHING;

-- Existing installations keep their configured values; only missing policy keys
-- are filled in so the running service never has to guess a default.
UPDATE settings SET value_json = '{"login_rate_limit_per_minute":30,"max_login_failures":5,"lockout_minutes":15,"idle_timeout_minutes":0,"trusted_proxies":[]}'::jsonb || value_json WHERE key='security';
