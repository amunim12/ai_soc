import { getToken } from './auth'

const BASE = 'http://localhost:8000'

function authHeaders(): Record<string, string> {
  const token = getToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { headers: authHeaders() })
  if (!res.ok) throw new Error(`API ${path} → ${res.status}`)
  return res.json()
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body)
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`API ${path} → ${res.status}: ${text}`)
  }
  return res.json()
}

async function put<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body)
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`API ${path} → ${res.status}: ${text}`)
  }
  return res.json()
}

async function del(path: string): Promise<void> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'DELETE',
    headers: authHeaders()
  })
  if (!res.ok && res.status !== 204) {
    const text = await res.text()
    throw new Error(`API ${path} → ${res.status}: ${text}`)
  }
}

async function postForm<T>(path: string, form: FormData): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: authHeaders(),
    body: form
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`API ${path} → ${res.status}: ${text}`)
  }
  return res.json()
}

// ── Types ──────────────────────────────────────────────────────────────────

export interface Metrics {
  total_alerts: number
  executed_playbooks: number
  dropped_alerts: number
  escalated_alerts: number
  pending_reviews: number
  avg_confidence: number
}

export interface ActivityPoint {
  hour: string
  count: number
  executed: number
  dropped: number
}

export interface PendingReview {
  review_id: string
  alert_id: string
  alert_json: string
  playbook_json: string
  confidence: number
  reason: string
  status: string
  expires_at: string | null
  created_at: string
}

export interface DecisionRequest {
  action: 'APPROVE' | 'EDIT' | 'REJECT' | 'ESCALATE'
  analyst_id: string
  notes?: string
  final_playbook_yaml?: string
}

export interface DecisionResponse {
  review_id: string
  action: string
  recorded: boolean
  message: string
}

export interface SoarExecution {
  execution_id: string
  workflow: string
  status: string
  results?: Record<string, unknown>
  received_at?: string
}

// ── Endpoints ──────────────────────────────────────────────────────────────

export interface LoginResponse {
  access_token: string
  token_type: string
  expires_in: number
  username: string
  role: string
}

export interface AgentRow {
  id: string
  name: string
  status: 'active' | 'disconnected' | 'never_connected'
  os: string
  ip: string
  last_seen: string
  alerts: number
  version?: string
}

export interface TopRule {
  rule: string
  count: number
}

// ── Native SIEM dashboard types ──────────────────────────────────────────

export interface SiemSummary {
  total_alerts: number
  executed_playbooks: number
  dropped_alerts: number
  escalated_alerts: number
  pending_reviews: number
  avg_confidence: number
  agents_total: number
  agents_active: number
  wazuh_online: boolean
}

export interface SiemAlert {
  review_id: string
  alert_id: string
  severity: string
  category: string
  rule_description: string
  agent_name: string
  agent_ip: string
  source_ip: string
  dest_ip: string
  user: string
  mitre_techniques: string[]
  confidence: number
  created_at: string
}

export interface SeverityPoint {
  hour: string
  CRITICAL: number
  HIGH: number
  MEDIUM: number
  LOW: number
}

export interface MitreStat {
  technique_id: string
  technique_name: string
  count: number
}

// ── Native SOAR dashboard types ───────────────────────────────────────────

export interface SoarWorkflow {
  id: string
  name: string
  description: string
  is_valid: boolean
  trigger_count: number
  action_count: number
  updated_at: string
}

export interface SoarExecutionDetail {
  execution_id: string
  workflow_id: string
  workflow: string
  status: string
  started_at: string
  completed_at: string
  step_count: number
  steps: {
    action_id: string
    label: string
    status: string
    started: string
    stopped: string
  }[]
}

export interface SoarTelemetryPoint {
  hour: string
  FINISHED: number
  FAILED: number
  ABORTED: number
  EXECUTING: number
}

export interface SoarAuditEntry {
  id: string
  type: 'pipeline' | 'soar_hitl'
  alert_id: string
  outcome: string
  analyst_id: string
  elapsed_s: number | null
  recorded_at: string
  execution_id: string | null
}

// ── Log Sources types ─────────────────────────────────────────────────────

export type SourceType = 'agent' | 'syslog' | 'windows_event' | 'api' | 'network' | 'cloud'
export type OsType = 'windows' | 'linux' | 'macos' | 'network' | 'cloud'
export type WazuhStatus = 'active' | 'disconnected' | 'never_connected' | 'pending' | 'unknown'

export interface LogSource {
  id: string
  name: string
  description: string
  source_type: SourceType
  host: string
  os_type: OsType | null
  wazuh_agent_id: string | null
  wazuh_status: WazuhStatus
  soar_enabled: boolean
  soar_actions: string[]
  soar_target_label: string | null
  tags: string[]
  created_at: string
  updated_at: string
}

export interface LogSourceCreate {
  name: string
  description?: string
  source_type: SourceType
  host: string
  os_type?: OsType | null
  soar_enabled?: boolean
  soar_actions?: string[]
  soar_target_label?: string | null
  tags?: string[]
}

export interface LogSourceUpdate {
  name?: string
  description?: string
  source_type?: SourceType
  host?: string
  os_type?: OsType | null
  soar_enabled?: boolean
  soar_actions?: string[]
  soar_target_label?: string | null
  tags?: string[]
}

export interface EnrollmentInstructions {
  log_source_id: string
  wazuh_manager_ip: string
  enrollment_key: string | null
  install_commands: string[]
  notes: string
}

export interface SoarTestResult {
  log_source_id: string
  reachable: boolean
  message: string
}

export interface LogSourceLiveStatus {
  source_id: string
  wazuh_status: WazuhStatus | 'unknown'
  wazuh_agent_id: string | null
  wazuh_reachable: boolean
  agent_name?: string
  agent_ip?: string
  last_keepalive?: string
  os?: string
  version?: string
  message?: string
}

export interface RagCollection {
  name: string
  count: number
}

export interface RagUploadResult {
  ingested_chunks: number
  collection: string
  filename: string
  sha256: string
  doc_id: string
}

export const api = {
  metrics: () => get<Metrics>('/api/metrics'),
  activity: (hours = 24) => get<ActivityPoint[]>(`/api/activity?hours=${hours}`),
  pendingReviews: () => get<PendingReview[]>('/api/hitl/pending'),
  submitDecision: (reviewId: string, body: DecisionRequest) =>
    post<DecisionResponse>(`/api/hitl/${reviewId}/decision`, body),
  executions: (limit = 50) => get<SoarExecution[]>(`/api/soar/executions?limit=${limit}`),
  health: () => get<{ status: string }>('/health'),

  // Auth
  login: (username: string, password: string) =>
    post<LoginResponse>('/api/auth/login', { username, password }),
  me: () => get<{ username: string; role: string; user_id: string }>('/api/auth/me'),

  // Legacy agent/rule helpers (used by old SiemView — kept for compat)
  agents: () => get<AgentRow[]>('/api/agents'),
  topRules: (limit = 10) => get<TopRule[]>(`/api/rules/top?limit=${limit}`),

  // Native SIEM dashboard endpoints
  siemSummary: () => get<SiemSummary>('/api/siem/summary'),
  siemAlerts: (limit = 100, severity?: string) =>
    get<SiemAlert[]>(`/api/siem/alerts?limit=${limit}${severity ? `&severity=${severity}` : ''}`),
  siemSeverity: (hours = 24) => get<SeverityPoint[]>(`/api/siem/severity?hours=${hours}`),
  siemMitre: (limit = 15) => get<MitreStat[]>(`/api/siem/mitre?limit=${limit}`),
  siemAgents: () => get<AgentRow[]>('/api/siem/agents'),

  // RAG
  ragCollections: () => get<RagCollection[]>('/api/rag/collections'),
  ragUpload: (form: FormData) => postForm<RagUploadResult>('/api/rag/upload', form),

  // Log Sources
  logSources: () => get<LogSource[]>('/api/log-sources'),
  logSourceCreate: (body: LogSourceCreate) => post<LogSource>('/api/log-sources', body),
  logSourceUpdate: (id: string, body: LogSourceUpdate) =>
    put<LogSource>(`/api/log-sources/${id}`, body),
  logSourceDelete: (id: string) => del(`/api/log-sources/${id}`),
  logSourceStatus: (id: string) => get<LogSourceLiveStatus>(`/api/log-sources/${id}/status`),
  logSourceEnroll: (id: string) => get<EnrollmentInstructions>(`/api/log-sources/${id}/enroll`),
  logSourceTestSoar: (id: string) => post<SoarTestResult>(`/api/log-sources/${id}/test-soar`, {}),
  logSoarActions: () => get<string[]>('/api/log-sources/soar-actions'),

  // Native SOAR dashboard
  soarWorkflows: () => get<SoarWorkflow[]>('/api/soar-dash/workflows'),
  soarExecutions: (limit = 100) =>
    get<SoarExecutionDetail[]>(`/api/soar-dash/executions?limit=${limit}`),
  soarTelemetry: (hours = 24) =>
    get<SoarTelemetryPoint[]>(`/api/soar-dash/telemetry?hours=${hours}`),
  soarAudit: (limit = 200) => get<SoarAuditEntry[]>(`/api/soar-dash/audit?limit=${limit}`)
}
