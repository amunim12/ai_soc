import { useCallback, useEffect, useRef, useState } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Legend,
} from 'recharts'
import {
  api,
  SoarWorkflow, SoarExecutionDetail, SoarTelemetryPoint, SoarAuditEntry,
} from '../lib/api'

type Tab = 'workflows' | 'telemetry' | 'audit'

// ── Status colour helpers ─────────────────────────────────────────────────────
const STATUS_COLOR: Record<string, string> = {
  FINISHED:  '#34d399',
  COMPLETED: '#34d399',
  FAILED:    '#f87171',
  ABORTED:   '#fbbf24',
  EXECUTING: '#38bdf8',
  PENDING:   '#8b5cf6',
  UNKNOWN:   '#475569',
}
const OUTCOME_COLOR: Record<string, string> = {
  EXECUTED:  '#34d399',
  FINISHED:  '#34d399',
  DROPPED:   '#64748b',
  ESCALATED: '#fbbf24',
  FAILED:    '#f87171',
  APPROVED:  '#34d399',
  REJECTED:  '#f87171',
  PENDING:   '#8b5cf6',
}

function statusColor(s?: string) {
  return STATUS_COLOR[(s ?? '').toUpperCase()] ?? '#475569'
}
function outcomeColor(s?: string) {
  return OUTCOME_COLOR[(s ?? '').toUpperCase()] ?? '#475569'
}

function timeAgo(iso: string) {
  if (!iso || iso === '—') return '—'
  const diff = Date.now() - new Date(iso).getTime()
  if (diff < 60_000)     return `${Math.floor(diff / 1_000)}s ago`
  if (diff < 3_600_000)  return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`
  return `${Math.floor(diff / 86_400_000)}d ago`
}

function elapsed(startIso: string, endIso: string): string {
  if (!startIso || !endIso) return '—'
  const ms = new Date(endIso).getTime() - new Date(startIso).getTime()
  if (ms < 0) return '—'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60_000)}m ${Math.floor((ms % 60_000) / 1000)}s`
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const c = statusColor(status)
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
      background: `${c}20`, color: c, border: `1px solid ${c}40`,
      textTransform: 'uppercase' as const, whiteSpace: 'nowrap' as const,
    }}>
      {status}
    </span>
  )
}

function ValidBadge({ valid }: { valid: boolean }) {
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4,
      background: valid ? 'rgba(52,211,153,0.1)' : 'rgba(248,113,113,0.1)',
      color:      valid ? '#34d399' : '#f87171',
      border:     `1px solid ${valid ? 'rgba(52,211,153,0.25)' : 'rgba(248,113,113,0.25)'}`,
    }}>
      {valid ? '✓ Valid' : '✕ Invalid'}
    </span>
  )
}

// ── Execution step timeline ───────────────────────────────────────────────────
function StepTimeline({ steps }: { steps: SoarExecutionDetail['steps'] }) {
  if (!steps.length) return (
    <div style={{ fontSize: 11, color: '#475569', padding: '8px 0' }}>No step data available</div>
  )
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      {steps.map((step, i) => {
        const c = statusColor(step.status)
        return (
          <div key={i} style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '6px 10px', borderRadius: 5,
            background: 'rgba(255,255,255,0.03)',
            border: `1px solid ${c}25`,
          }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: c, flexShrink: 0 }} />
            <span style={{ flex: 1, fontSize: 11, color: '#94a3b8' }}>
              {step.label || step.action_id || `Step ${i + 1}`}
            </span>
            <StatusBadge status={step.status} />
            {step.started && step.stopped && (
              <span style={{ fontSize: 10, color: '#475569', fontFamily: 'monospace' }}>
                {elapsed(step.started, step.stopped)}
              </span>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────
interface ShuffleViewProps { onBack?: () => void }

export default function ShuffleView({ onBack }: ShuffleViewProps) {
  const [tab, setTab] = useState<Tab>('workflows')

  const [workflows,  setWorkflows]  = useState<SoarWorkflow[]>([])
  const [executions, setExecutions] = useState<SoarExecutionDetail[]>([])
  const [telemetry,  setTelemetry]  = useState<SoarTelemetryPoint[]>([])
  const [audit,      setAudit]      = useState<SoarAuditEntry[]>([])
  const [selected,   setSelected]   = useState<SoarExecutionDetail | null>(null)
  const [loading,    setLoading]    = useState(false)
  const [shuffleUp,  setShuffleUp]  = useState<boolean | null>(null)

  // ── Fetch helpers ─────────────────────────────────────────────────────────
  const fetchWorkflows = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.soarWorkflows()
      setWorkflows(data)
      setShuffleUp(true)
    } catch { setShuffleUp(false) }
    finally { setLoading(false) }
  }, [])

  const fetchTelemetry = useCallback(async () => {
    setLoading(true)
    try {
      const [execs, tele] = await Promise.all([
        api.soarExecutions(150),
        api.soarTelemetry(24),
      ])
      setExecutions(execs)
      setTelemetry(tele)
    } catch { /* backend offline */ }
    finally { setLoading(false) }
  }, [])

  const fetchAudit = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.soarAudit(300)
      setAudit(data)
    } catch { /* backend offline */ }
    finally { setLoading(false) }
  }, [])

  // Auto-poll active tab
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  useEffect(() => {
    if (timerRef.current) clearInterval(timerRef.current)
    const [fn, ms] = (
      tab === 'workflows' ? [fetchWorkflows, 500] :
      tab === 'telemetry' ? [fetchTelemetry, 500] :
                            [fetchAudit,     500]
    ) as [() => void, number]
    fn()
    timerRef.current = setInterval(fn, ms)
    return () => { if (timerRef.current) clearInterval(timerRef.current) }
  }, [tab, fetchWorkflows, fetchTelemetry, fetchAudit])

  // ── Derived stats ─────────────────────────────────────────────────────────
  const totalFinished  = executions.filter(e => ['FINISHED','COMPLETED'].includes(e.status)).length
  const totalFailed    = executions.filter(e => e.status === 'FAILED').length
  const totalExecuting = executions.filter(e => e.status === 'EXECUTING').length
  const successRate    = executions.length
    ? Math.round((totalFinished / executions.length) * 100) : 0

  // ── Tab styling ─────────────────────────────────────────────────────────
  const TABS: { id: Tab; label: string; icon: string }[] = [
    { id: 'workflows', label: 'Workflows',        icon: '⬡' },
    { id: 'telemetry', label: 'Execution Telemetry', icon: '◷' },
    { id: 'audit',     label: 'Trigger Audit Log', icon: '≡' },
  ]

  function tabStyle(id: Tab) {
    const active = tab === id
    return {
      padding: '5px 14px', borderRadius: 5, fontSize: 12, fontWeight: 600 as const,
      cursor: 'pointer' as const,
      border: `1px solid ${active ? 'rgba(52,211,153,0.4)' : 'rgba(255,255,255,0.06)'}`,
      background: active ? 'rgba(52,211,153,0.1)' : 'transparent',
      color: active ? '#34d399' : '#475569',
      transition: 'all 0.15s',
      display: 'flex' as const, alignItems: 'center' as const, gap: 6,
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

      {/* ── Topbar ──────────────────────────────────────────────────────── */}
      <div className="topbar" style={{ paddingLeft: 20, gap: 10, flexShrink: 0, flexWrap: 'wrap', minHeight: 52 }}>
        {onBack && (
          <button className="btn btn-ghost" style={{ fontSize: 12, padding: '4px 10px' }} onClick={onBack}>
            ← Back
          </button>
        )}

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0' }}>SOAR Dashboard</span>
          {shuffleUp === true && (
            <span style={{
              fontSize: 10, padding: '2px 8px', borderRadius: 99, fontWeight: 600,
              background: 'rgba(52,211,153,0.1)', color: '#34d399',
              border: '1px solid rgba(52,211,153,0.2)',
            }}>● Connected</span>
          )}
          {shuffleUp === false && (
            <span style={{
              fontSize: 10, padding: '2px 8px', borderRadius: 99, fontWeight: 600,
              background: 'rgba(251,191,36,0.1)', color: '#fbbf24',
              border: '1px solid rgba(251,191,36,0.2)',
            }}>◌ Pipeline Data</span>
          )}
        </div>

        <div style={{ display: 'flex', gap: 5, marginLeft: 8 }}>
          {TABS.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={tabStyle(t.id)}>
              <span style={{ fontSize: 13 }}>{t.icon}</span>{t.label}
            </button>
          ))}
        </div>

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
          {loading && <div className="spinner" style={{ width: 12, height: 12, borderWidth: 1.5 }} />}
        </div>
      </div>

      {/* ── Workflows tab ───────────────────────────────────────────────── */}
      {tab === 'workflows' && (
        <div style={{ flex: 1, overflow: 'auto', padding: 20 }} className="animate-in">
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 16, fontWeight: 700, color: '#e2e8f0' }}>
              Incident Response Workflows
            </div>
            <div style={{ fontSize: 12, color: '#64748b' }}>
              Automated playbooks registered in Shuffle SOAR
            </div>
          </div>

          {workflows.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">⬡</div>
              <span>No workflows found — run <code style={{ color: '#94a3b8' }}>register_shuffle_workflows.py</code></span>
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 14 }}>
              {workflows.map(wf => (
                <div key={wf.id} className="glass glass-hover" style={{
                  padding: '18px 20px',
                  borderTop: `2px solid ${wf.is_valid ? '#34d399' : '#f87171'}`,
                }}>
                  {/* Header */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                    <div style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0', lineHeight: 1.3 }}>
                      {wf.name}
                    </div>
                    <ValidBadge valid={wf.is_valid} />
                  </div>

                  {/* Description */}
                  {wf.description && (
                    <div style={{ fontSize: 12, color: '#64748b', marginBottom: 12, lineHeight: 1.5 }}>
                      {wf.description}
                    </div>
                  )}

                  {/* Stats row */}
                  <div style={{ display: 'flex', gap: 16, fontSize: 11 }}>
                    {[
                      { label: 'Triggers', value: wf.trigger_count, color: '#8b5cf6' },
                      { label: 'Actions',  value: wf.action_count,  color: '#38bdf8' },
                    ].map(s => (
                      <div key={s.label} style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                        <span style={{ color: '#475569', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{s.label}</span>
                        <span style={{ fontWeight: 700, fontSize: 16, color: s.color }}>{s.value}</span>
                      </div>
                    ))}
                    {wf.updated_at && (
                      <div style={{ marginLeft: 'auto', display: 'flex', flexDirection: 'column', gap: 2, alignItems: 'flex-end' }}>
                        <span style={{ color: '#475569', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Updated</span>
                        <span style={{ fontSize: 11, color: '#64748b' }}>{timeAgo(wf.updated_at)}</span>
                      </div>
                    )}
                  </div>

                  {/* ID footer */}
                  <div style={{ marginTop: 12, paddingTop: 10, borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                    <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#334155' }}>
                      {wf.id.slice(0, 32)}{wf.id.length > 32 ? '…' : ''}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Telemetry tab ────────────────────────────────────────────────── */}
      {tab === 'telemetry' && (
        <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
          {/* Left: charts + summary */}
          <div style={{ flex: 1, overflow: 'auto', padding: 20 }} className="animate-in">
            {/* Summary stat row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: 10, marginBottom: 20 }}>
              {[
                { label: 'Total Executions', value: executions.length, color: '#8b5cf6' },
                { label: 'Successful',        value: totalFinished,     color: '#34d399' },
                { label: 'Failed',            value: totalFailed,       color: '#f87171' },
                { label: 'In Progress',       value: totalExecuting,    color: '#38bdf8' },
                { label: 'Success Rate',      value: `${successRate}%`, color: successRate >= 80 ? '#34d399' : '#fbbf24' },
              ].map(s => (
                <div key={s.label} className="glass" style={{ padding: '12px 14px' }}>
                  <div style={{ fontSize: 9, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
                    {s.label}
                  </div>
                  <div style={{ fontSize: 22, fontWeight: 800, color: s.color }}>{s.value}</div>
                </div>
              ))}
            </div>

            {/* 24-hour area chart */}
            <div className="glass" style={{ padding: 20, marginBottom: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                <div className="section-title">24-Hour Execution Volume</div>
                <div style={{ display: 'flex', gap: 12 }}>
                  {[
                    { label: 'Finished', color: '#34d399' },
                    { label: 'Failed',   color: '#f87171' },
                    { label: 'Aborted',  color: '#fbbf24' },
                  ].map(l => (
                    <span key={l.label} style={{ fontSize: 11, color: l.color, display: 'flex', alignItems: 'center', gap: 4 }}>
                      <span style={{ width: 8, height: 8, borderRadius: 2, background: l.color, display: 'inline-block' }} />
                      {l.label}
                    </span>
                  ))}
                </div>
              </div>
              {telemetry.length === 0 ? (
                <div className="empty-state" style={{ padding: '28px 0' }}>
                  <div className="empty-state-icon">◷</div>
                  <span>No execution data yet</span>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={telemetry} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                    <defs>
                      {[
                        { key: 'FINISHED', col: '#34d399' },
                        { key: 'FAILED',   col: '#f87171' },
                        { key: 'ABORTED',  col: '#fbbf24' },
                      ].map(({ key, col }) => (
                        <linearGradient key={key} id={`soar-grad-${key}`} x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%"  stopColor={col} stopOpacity={0.3} />
                          <stop offset="95%" stopColor={col} stopOpacity={0}   />
                        </linearGradient>
                      ))}
                    </defs>
                    <XAxis dataKey="hour" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={{ background: '#0d1117', border: '1px solid rgba(52,211,153,0.2)', borderRadius: 6, fontSize: 11, color: '#e2e8f0' }} />
                    <Area type="monotone" dataKey="FINISHED" stroke="#34d399" strokeWidth={1.5} fill="url(#soar-grad-FINISHED)" name="Finished" />
                    <Area type="monotone" dataKey="FAILED"   stroke="#f87171" strokeWidth={1.5} fill="url(#soar-grad-FAILED)"   name="Failed" />
                    <Area type="monotone" dataKey="ABORTED"  stroke="#fbbf24" strokeWidth={1.5} fill="url(#soar-grad-ABORTED)"  name="Aborted" />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>

            {/* Execution list */}
            <div className="glass" style={{ overflow: 'hidden' }}>
              <div style={{
                display: 'grid', gridTemplateColumns: '1fr 110px 90px 80px 70px',
                gap: '0 10px', padding: '9px 14px',
                background: 'rgba(255,255,255,0.03)',
                borderBottom: '1px solid rgba(255,255,255,0.06)',
                fontSize: 10, fontWeight: 700, color: '#475569',
                textTransform: 'uppercase' as const, letterSpacing: '0.06em',
              }}>
                <div>Workflow</div><div>Execution ID</div>
                <div>Status</div><div>Duration</div><div>Started</div>
              </div>

              {executions.length === 0 ? (
                <div className="empty-state" style={{ padding: '28px 0' }}>
                  <div className="empty-state-icon">📜</div>
                  <span>No executions yet</span>
                </div>
              ) : (
                executions.map((ex, i) => (
                  <div
                    key={ex.execution_id}
                    className="glass-hover"
                    onClick={() => setSelected(selected?.execution_id === ex.execution_id ? null : ex)}
                    style={{
                      display: 'grid', gridTemplateColumns: '1fr 110px 90px 80px 70px',
                      gap: '0 10px', padding: '10px 14px',
                      borderBottom: i < executions.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
                      fontSize: 12, alignItems: 'center', cursor: 'pointer',
                      background: selected?.execution_id === ex.execution_id ? 'rgba(52,211,153,0.05)' : undefined,
                      borderLeft: `2px solid ${statusColor(ex.status)}`,
                    }}
                  >
                    <div style={{ fontWeight: 600, color: '#a5f3fc' }}>{ex.workflow || '—'}</div>
                    <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#475569' }}>
                      {ex.execution_id.slice(0, 12)}…
                    </div>
                    <div><StatusBadge status={ex.status} /></div>
                    <div style={{ fontSize: 11, color: '#64748b', fontFamily: 'monospace' }}>
                      {elapsed(ex.started_at, ex.completed_at)}
                    </div>
                    <div style={{ fontSize: 10, color: '#475569' }}>{timeAgo(ex.started_at)}</div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Right: execution detail panel */}
          {selected && (
            <div className="glass animate-in" style={{
              width: 340, flexShrink: 0, overflow: 'auto',
              padding: 18, display: 'flex', flexDirection: 'column', gap: 14,
              borderLeft: '1px solid rgba(255,255,255,0.06)',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div className="section-title" style={{ marginBottom: 0 }}>Execution Detail</div>
                <button className="btn btn-ghost" style={{ padding: '3px 8px', fontSize: 11 }} onClick={() => setSelected(null)}>✕</button>
              </div>

              {[
                { label: 'Workflow',    value: selected.workflow || '—' },
                { label: 'Status',      value: selected.status },
                { label: 'Started',     value: timeAgo(selected.started_at) },
                { label: 'Duration',    value: elapsed(selected.started_at, selected.completed_at) },
                { label: 'Steps',       value: String(selected.step_count) },
              ].map(({ label, value }) => (
                <div key={label}>
                  <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 3 }}>{label}</div>
                  <div style={{ fontSize: 13, color: '#e2e8f0', fontWeight: 600 }}>{value}</div>
                </div>
              ))}

              <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 12 }}>
                <div className="section-title" style={{ marginBottom: 8 }}>Step Timeline</div>
                <StepTimeline steps={selected.steps} />
              </div>

              <div>
                <div style={{ fontSize: 10, color: '#334155', marginBottom: 2 }}>Execution ID</div>
                <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#334155', wordBreak: 'break-all' }}>
                  {selected.execution_id}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Audit Log tab ───────────────────────────────────────────────── */}
      {tab === 'audit' && (
        <div style={{ flex: 1, overflow: 'auto', padding: 20 }} className="animate-in">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div>
              <div style={{ fontSize: 16, fontWeight: 700, color: '#e2e8f0' }}>Trigger Audit Log</div>
              <div style={{ fontSize: 12, color: '#64748b' }}>
                All pipeline executions and SOAR HITL gate events · refreshes every 10 s
              </div>
            </div>
            <span style={{
              fontSize: 11, fontWeight: 700, padding: '4px 10px', borderRadius: 99,
              background: 'rgba(139,92,246,0.1)', color: '#a78bfa',
              border: '1px solid rgba(139,92,246,0.2)',
            }}>
              {audit.length} entries
            </span>
          </div>

          {audit.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">≡</div>
              <span>No audit entries yet</span>
            </div>
          ) : (
            <div className="glass" style={{ overflow: 'hidden' }}>
              {/* Header */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: '80px 90px 1fr 100px 110px 80px 90px',
                gap: '0 10px', padding: '9px 14px',
                background: 'rgba(255,255,255,0.03)',
                borderBottom: '1px solid rgba(255,255,255,0.06)',
                fontSize: 10, fontWeight: 700, color: '#475569',
                textTransform: 'uppercase' as const, letterSpacing: '0.06em',
              }}>
                <div>Type</div><div>Outcome</div><div>Alert ID</div>
                <div>Analyst</div><div>Execution ID</div><div>Elapsed</div><div>Time</div>
              </div>

              {audit.map((entry, i) => {
                const oc = outcomeColor(entry.outcome)
                return (
                  <div
                    key={entry.id}
                    className="glass-hover"
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '80px 90px 1fr 100px 110px 80px 90px',
                      gap: '0 10px', padding: '10px 14px',
                      borderBottom: i < audit.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
                      fontSize: 11, alignItems: 'center',
                    }}
                  >
                    {/* Type badge */}
                    <div>
                      <span style={{
                        fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 3,
                        background: entry.type === 'pipeline' ? 'rgba(139,92,246,0.15)' : 'rgba(56,189,248,0.12)',
                        color:      entry.type === 'pipeline' ? '#a78bfa' : '#38bdf8',
                        border:     `1px solid ${entry.type === 'pipeline' ? 'rgba(139,92,246,0.25)' : 'rgba(56,189,248,0.2)'}`,
                        textTransform: 'uppercase' as const,
                      }}>
                        {entry.type === 'pipeline' ? 'pipeline' : 'soar'}
                      </span>
                    </div>

                    {/* Outcome */}
                    <div>
                      <span style={{
                        fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 3,
                        background: `${oc}15`, color: oc, border: `1px solid ${oc}30`,
                        textTransform: 'uppercase' as const,
                      }}>
                        {entry.outcome}
                      </span>
                    </div>

                    <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#64748b' }}>
                      {entry.alert_id.slice(0, 22)}…
                    </div>
                    <div style={{ fontSize: 11, color: '#94a3b8' }}>{entry.analyst_id}</div>
                    <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#475569' }}>
                      {entry.execution_id ? entry.execution_id.slice(0, 12) + '…' : '—'}
                    </div>
                    <div style={{ fontSize: 11, color: '#64748b' }}>
                      {entry.elapsed_s != null ? `${entry.elapsed_s}s` : '—'}
                    </div>
                    <div style={{ fontSize: 10, color: '#475569' }}>{timeAgo(entry.recorded_at)}</div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
