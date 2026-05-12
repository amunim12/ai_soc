import { useCallback, useEffect, useRef, useState } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell,
} from 'recharts'
import {
  api,
  SiemSummary, SiemAlert, SeverityPoint, MitreStat, AgentRow,
} from '../lib/api'

type Tab = 'overview' | 'alerts' | 'agents' | 'mitre'

// ── Colour maps ───────────────────────────────────────────────────────────────
const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#f87171',
  HIGH:     '#fbbf24',
  MEDIUM:   '#38bdf8',
  LOW:      '#34d399',
}
const AGENT_STATUS_COLOR: Record<string, string> = {
  active:          '#34d399',
  disconnected:    '#f87171',
  never_connected: '#64748b',
}

function sevColor(s?: string) { return SEV_COLOR[(s ?? '').toUpperCase()] ?? '#64748b' }

function timeAgo(iso: string) {
  if (!iso || iso === '—') return '—'
  const diff = Date.now() - new Date(iso).getTime()
  if (diff < 60_000)     return `${Math.floor(diff / 1_000)}s ago`
  if (diff < 3_600_000)  return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`
  return `${Math.floor(diff / 86_400_000)}d ago`
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatCard({
  label, value, sub, color, icon,
}: { label: string; value: string | number; sub?: string; color: string; icon: string }) {
  return (
    <div className="glass" style={{ padding: '16px 18px', position: 'relative', overflow: 'hidden' }}>
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 2,
        background: color,
      }} />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 6 }}>
            {label}
          </div>
          <div style={{ fontSize: 26, fontWeight: 800, color, lineHeight: 1 }}>{value}</div>
          {sub && <div style={{ fontSize: 11, color: '#475569', marginTop: 4 }}>{sub}</div>}
        </div>
        <span style={{ fontSize: 22, opacity: 0.35 }}>{icon}</span>
      </div>
    </div>
  )
}

function SeverityBadge({ severity }: { severity: string }) {
  const c = sevColor(severity)
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
      background: `${c}20`, color: c, border: `1px solid ${c}40`,
      textTransform: 'uppercase' as const, whiteSpace: 'nowrap' as const,
    }}>
      {severity}
    </span>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

interface SiemViewProps { onBack?: () => void }

export default function SiemView({ onBack }: SiemViewProps) {
  const [tab, setTab] = useState<Tab>('overview')

  // Per-tab data
  const [summary,    setSummary]   = useState<SiemSummary | null>(null)
  const [sevData,    setSevData]   = useState<SeverityPoint[]>([])
  const [alerts,     setAlerts]    = useState<SiemAlert[]>([])
  const [agents,     setAgents]    = useState<AgentRow[]>([])
  const [mitre,      setMitre]     = useState<MitreStat[]>([])

  // Alert-feed controls
  const [sevFilter,  setSevFilter] = useState<string>('ALL')
  const [search,     setSearch]    = useState('')
  const [loadingMap, setLoadingMap]= useState<Record<Tab, boolean>>({
    overview: false, alerts: false, agents: false, mitre: false,
  })

  const setLoading = (t: Tab, v: boolean) =>
    setLoadingMap(prev => ({ ...prev, [t]: v }))

  // ── Fetch functions ─────────────────────────────────────────────────────

  const fetchOverview = useCallback(async () => {
    setLoading('overview', true)
    try {
      const [s, sv] = await Promise.all([api.siemSummary(), api.siemSeverity(24)])
      setSummary(s)
      setSevData(sv)
    } catch { /* backend offline */ }
    finally { setLoading('overview', false) }
  }, [])

  const fetchAlerts = useCallback(async () => {
    setLoading('alerts', true)
    try {
      const data = await api.siemAlerts(200)
      setAlerts(data)
    } catch { /* backend offline */ }
    finally { setLoading('alerts', false) }
  }, [])

  const fetchAgents = useCallback(async () => {
    setLoading('agents', true)
    try {
      const data = await api.siemAgents()
      setAgents(data)
    } catch { /* backend offline */ }
    finally { setLoading('agents', false) }
  }, [])

  const fetchMitre = useCallback(async () => {
    setLoading('mitre', true)
    try {
      const data = await api.siemMitre(20)
      setMitre(data)
    } catch { /* backend offline */ }
    finally { setLoading('mitre', false) }
  }, [])

  // Auto-poll each tab
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  useEffect(() => {
    if (timerRef.current) clearInterval(timerRef.current)

    const [fn, interval] = (
      tab === 'overview' ? [fetchOverview, 500] :
      tab === 'alerts'   ? [fetchAlerts,   500] :
      tab === 'agents'   ? [fetchAgents,   500] :
                           [fetchMitre,    500]
    ) as [() => void, number]

    fn()
    timerRef.current = setInterval(fn, interval)
    return () => { if (timerRef.current) clearInterval(timerRef.current) }
  }, [tab, fetchOverview, fetchAlerts, fetchAgents, fetchMitre])

  // ── Filtered alerts ─────────────────────────────────────────────────────
  const filteredAlerts = alerts.filter(a => {
    const matchSev  = sevFilter === 'ALL' || a.severity === sevFilter
    const q         = search.toLowerCase()
    const matchText = !q ||
      a.rule_description.toLowerCase().includes(q) ||
      a.agent_name.toLowerCase().includes(q) ||
      a.source_ip.includes(q) ||
      a.category.toLowerCase().includes(q)
    return matchSev && matchText
  })

  // ── Tab styling ─────────────────────────────────────────────────────────
  const TABS: { id: Tab; label: string; icon: string }[] = [
    { id: 'overview', label: 'Overview',      icon: '◉' },
    { id: 'alerts',   label: 'Alert Feed',    icon: '⚡' },
    { id: 'agents',   label: 'Agents',        icon: '⬡' },
    { id: 'mitre',    label: 'MITRE ATT&CK',  icon: '⊞' },
  ]

  function tabStyle(id: Tab) {
    const active = tab === id
    return {
      padding: '5px 14px', borderRadius: 5, fontSize: 12, fontWeight: 600 as const,
      cursor: 'pointer' as const,
      border: `1px solid ${active ? 'rgba(139,92,246,0.4)' : 'rgba(255,255,255,0.06)'}`,
      background: active ? 'rgba(139,92,246,0.12)' : 'transparent',
      color: active ? '#a78bfa' : '#475569',
      transition: 'all 0.15s',
      display: 'flex' as const, alignItems: 'center' as const, gap: 6,
    }
  }

  const isLoading = loadingMap[tab]

  // ── Render ──────────────────────────────────────────────────────────────
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
          <span style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0' }}>SIEM Dashboard</span>
          {summary?.wazuh_online ? (
            <span style={{
              fontSize: 10, padding: '2px 8px', borderRadius: 99, fontWeight: 600,
              background: 'rgba(52,211,153,0.1)', color: '#34d399',
              border: '1px solid rgba(52,211,153,0.2)',
            }}>
              ● Wazuh Connected
            </span>
          ) : (
            <span style={{
              fontSize: 10, padding: '2px 8px', borderRadius: 99, fontWeight: 600,
              background: 'rgba(251,191,36,0.1)', color: '#fbbf24',
              border: '1px solid rgba(251,191,36,0.2)',
            }}>
              ◌ Pipeline Data
            </span>
          )}
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', gap: 5, marginLeft: 8 }}>
          {TABS.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={tabStyle(t.id)}>
              <span style={{ fontSize: 13 }}>{t.icon}</span>{t.label}
            </button>
          ))}
        </div>

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
          {isLoading && <div className="spinner" style={{ width: 12, height: 12, borderWidth: 1.5 }} />}
          <span style={{ fontSize: 11, color: '#334155', fontFamily: 'monospace' }}>
            auto-refresh
          </span>
        </div>
      </div>

      {/* ── Overview tab ────────────────────────────────────────────────── */}
      {tab === 'overview' && (
        <div style={{ flex: 1, overflow: 'auto', padding: 20 }} className="animate-in">

          {/* Headline stat cards */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))',
            gap: 12, marginBottom: 20,
          }}>
            <StatCard label="Total Alerts"      value={summary?.total_alerts      ?? 0} color="#8b5cf6" icon="📡" sub="All-time pipeline" />
            <StatCard label="Executed"           value={summary?.executed_playbooks ?? 0} color="#34d399" icon="▶"  sub="SOAR workflows triggered" />
            <StatCard label="Pending HITL"       value={summary?.pending_reviews   ?? 0} color="#fbbf24" icon="⏳" sub="Awaiting decision" />
            <StatCard label="Dropped"            value={summary?.dropped_alerts    ?? 0} color="#64748b" icon="🚫" sub="Noise / duplicates" />
            <StatCard label="Escalated"          value={summary?.escalated_alerts  ?? 0} color="#f87171" icon="⬆"  sub="Senior analyst" />
            <StatCard label="Agents Active"      value={`${summary?.agents_active ?? 0}/${summary?.agents_total ?? 0}`} color="#38bdf8" icon="⬡"  sub="Wazuh endpoints" />
          </div>

          {/* 24-hour severity area chart */}
          <div className="glass" style={{ padding: 20, marginBottom: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div className="section-title">24-Hour Alert Volume by Severity</div>
              <div style={{ display: 'flex', gap: 12 }}>
                {Object.entries(SEV_COLOR).map(([sev, col]) => (
                  <span key={sev} style={{ fontSize: 11, color: col, display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span style={{ width: 8, height: 8, borderRadius: 2, background: col, display: 'inline-block' }} />
                    {sev}
                  </span>
                ))}
              </div>
            </div>
            {sevData.length === 0 ? (
              <div className="empty-state" style={{ padding: '28px 0' }}>
                <div className="empty-state-icon">📊</div>
                <span>No data yet — alerts will populate this chart</span>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={sevData} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                  <defs>
                    {Object.entries(SEV_COLOR).map(([sev, col]) => (
                      <linearGradient key={sev} id={`grad-${sev}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor={col} stopOpacity={0.25} />
                        <stop offset="95%" stopColor={col} stopOpacity={0}    />
                      </linearGradient>
                    ))}
                  </defs>
                  <XAxis dataKey="hour" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#0d1117', border: '1px solid rgba(139,92,246,0.2)', borderRadius: 6, fontSize: 11, color: '#e2e8f0' }} />
                  {Object.entries(SEV_COLOR).map(([sev, col]) => (
                    <Area key={sev} type="monotone" dataKey={sev} stroke={col} strokeWidth={1.5}
                      fill={`url(#grad-${sev})`} name={sev} stackId="1" />
                  ))}
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Confidence health */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 14 }}>
            <div className="glass" style={{ padding: 18 }}>
              <div className="section-title" style={{ marginBottom: 12 }}>Avg Playbook Confidence</div>
              {summary && (
                <>
                  <div style={{ fontSize: 40, fontWeight: 900, color: summary.avg_confidence >= 0.85 ? '#34d399' : '#fbbf24', lineHeight: 1 }}>
                    {Math.round(summary.avg_confidence * 100)}%
                  </div>
                  <div style={{ fontSize: 11, color: '#64748b', marginTop: 6 }}>
                    {summary.avg_confidence >= 0.85 ? 'Above auto-approve threshold' : 'Below 85% — HITL required'}
                  </div>
                  {/* Progress bar */}
                  <div style={{ marginTop: 12, height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
                    <div style={{
                      height: '100%', borderRadius: 2,
                      width: `${Math.round(summary.avg_confidence * 100)}%`,
                      background: summary.avg_confidence >= 0.85
                        ? 'linear-gradient(90deg, #34d399, #38bdf8)'
                        : 'linear-gradient(90deg, #fbbf24, #f87171)',
                      transition: 'width 0.6s ease',
                    }} />
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Alert Feed tab ──────────────────────────────────────────────── */}
      {tab === 'alerts' && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

          {/* Controls */}
          <div style={{ padding: '14px 20px 10px', display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', flexShrink: 0 }}>
            {/* Search */}
            <input
              className="input"
              style={{ width: 240, padding: '6px 10px', fontSize: 12 }}
              placeholder="Search rule, agent, IP…"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />

            {/* Severity filter pills */}
            <div style={{ display: 'flex', gap: 5 }}>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => {
                const active = sevFilter === s
                const col    = s === 'ALL' ? '#8b5cf6' : sevColor(s)
                return (
                  <button key={s} onClick={() => setSevFilter(s)} style={{
                    padding: '4px 10px', borderRadius: 99, fontSize: 11, fontWeight: 700,
                    cursor: 'pointer', border: `1px solid ${active ? col : col + '30'}`,
                    background: active ? `${col}20` : 'transparent',
                    color: active ? col : '#475569', transition: 'all 0.12s',
                  }}>
                    {s}
                  </button>
                )
              })}
            </div>

            <span style={{ marginLeft: 'auto', fontSize: 11, color: '#475569' }}>
              {filteredAlerts.length} alerts · refreshes every 5 s
            </span>
          </div>

          {/* Table */}
          <div style={{ flex: 1, overflow: 'auto', padding: '0 20px 20px' }}>
            {filteredAlerts.length === 0 ? (
              <div className="empty-state">
                <div className="empty-state-icon">✓</div>
                <span>{alerts.length === 0 ? 'No alerts in pipeline yet' : 'No alerts match filter'}</span>
              </div>
            ) : (
              <div className="glass" style={{ overflow: 'hidden' }}>
                {/* Header */}
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: '90px 1fr 100px 110px 110px 80px 90px',
                  gap: '0 10px', padding: '9px 14px',
                  background: 'rgba(255,255,255,0.03)',
                  borderBottom: '1px solid rgba(255,255,255,0.06)',
                  fontSize: 10, fontWeight: 700, color: '#475569',
                  textTransform: 'uppercase' as const, letterSpacing: '0.06em',
                }}>
                  <div>Severity</div><div>Rule</div><div>Agent</div>
                  <div>Source IP</div><div>Category</div><div>Conf</div><div>Time</div>
                </div>

                {filteredAlerts.map((a, i) => (
                  <div
                    key={a.review_id}
                    className="glass-hover"
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '90px 1fr 100px 110px 110px 80px 90px',
                      gap: '0 10px', padding: '10px 14px',
                      borderBottom: i < filteredAlerts.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
                      fontSize: 12, alignItems: 'center',
                      borderLeft: `2px solid ${sevColor(a.severity)}`,
                    }}
                  >
                    <div><SeverityBadge severity={a.severity} /></div>
                    <div style={{ color: '#c4b5fd', fontSize: 11, lineHeight: 1.4 }}>
                      {a.rule_description.length > 60 ? a.rule_description.slice(0, 60) + '…' : a.rule_description}
                    </div>
                    <div style={{ fontSize: 11, color: '#94a3b8' }}>{a.agent_name}</div>
                    <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#64748b' }}>{a.source_ip}</div>
                    <div style={{ fontSize: 11, color: '#64748b' }}>{a.category}</div>
                    <div style={{ fontSize: 11, color: a.confidence >= 0.85 ? '#34d399' : '#fbbf24' }}>
                      {Math.round(a.confidence * 100)}%
                    </div>
                    <div style={{ fontSize: 10, color: '#475569' }}>{timeAgo(a.created_at)}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Agents tab ──────────────────────────────────────────────────── */}
      {tab === 'agents' && (
        <div style={{ flex: 1, overflow: 'auto', padding: 20 }} className="animate-in">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div>
              <div style={{ fontSize: 16, fontWeight: 700, color: '#e2e8f0' }}>Agent Health Matrix</div>
              <div style={{ fontSize: 12, color: '#64748b' }}>
                {summary?.wazuh_online ? 'Live from Wazuh Manager REST API' : 'Derived from pipeline alert data'} · refreshes every 12 s
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              {[
                { label: 'Active',       count: agents.filter(a => a.status === 'active').length,          color: '#34d399' },
                { label: 'Disconnected', count: agents.filter(a => a.status === 'disconnected').length,    color: '#f87171' },
                { label: 'Never Seen',   count: agents.filter(a => a.status === 'never_connected').length, color: '#64748b' },
              ].map(s => (
                <span key={s.label} style={{
                  fontSize: 11, fontWeight: 700, padding: '4px 10px', borderRadius: 99,
                  background: `${s.color}15`, color: s.color, border: `1px solid ${s.color}30`,
                }}>
                  {s.count} {s.label}
                </span>
              ))}
            </div>
          </div>

          {agents.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">⬡</div>
              <span>No agents found — pipeline alerts will populate this view</span>
            </div>
          ) : (
            /* Card grid */
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
              {agents.map(agent => {
                const statusColor = AGENT_STATUS_COLOR[agent.status] ?? '#64748b'
                return (
                  <div key={agent.id} className="glass glass-hover" style={{
                    padding: '14px 16px',
                    borderTop: `2px solid ${statusColor}`,
                  }}>
                    {/* Header row */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div style={{
                          width: 8, height: 8, borderRadius: '50%', background: statusColor,
                          boxShadow: `0 0 8px ${statusColor}90`,
                        }} />
                        <span style={{ fontWeight: 700, fontSize: 13, color: '#e2e8f0' }}>{agent.name}</span>
                      </div>
                      <span style={{
                        fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 600,
                        background: `${statusColor}18`, color: statusColor,
                        border: `1px solid ${statusColor}35`, textTransform: 'capitalize' as const,
                      }}>
                        {agent.status.replace('_', ' ')}
                      </span>
                    </div>

                    {/* Detail grid */}
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 10px', fontSize: 11 }}>
                      {[
                        { label: 'ID',       value: agent.id.slice(0, 12) },
                        { label: 'IP',       value: agent.ip,    mono: true },
                        { label: 'OS',       value: agent.os,    span: true },
                        { label: 'Last Seen',value: timeAgo(agent.last_seen) },
                        { label: 'Alerts',   value: String(agent.alerts) },
                        { label: 'Version',  value: agent.version ?? '—' },
                      ].map(item => (
                        <div key={item.label} style={item.span ? { gridColumn: '1 / -1' } : {}}>
                          <div style={{ fontSize: 9, color: '#475569', textTransform: 'uppercase' as const, letterSpacing: '0.05em', marginBottom: 1 }}>
                            {item.label}
                          </div>
                          <div style={{
                            color: '#94a3b8', fontFamily: item.mono ? 'monospace' : undefined,
                            fontSize: item.mono ? 10 : 11,
                          }}>
                            {item.value || '—'}
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Alert count bar */}
                    {agent.alerts > 0 && (
                      <div style={{ marginTop: 10 }}>
                        <div style={{ height: 3, background: 'rgba(255,255,255,0.05)', borderRadius: 2 }}>
                          <div style={{
                            height: '100%', borderRadius: 2,
                            width: `${Math.min(100, (agent.alerts / 20) * 100)}%`,
                            background: agent.alerts >= 8
                              ? 'linear-gradient(90deg, #f87171, #fbbf24)'
                              : 'linear-gradient(90deg, #fbbf24, #34d399)',
                          }} />
                        </div>
                        <div style={{ fontSize: 10, color: '#475569', marginTop: 3 }}>
                          {agent.alerts} alert{agent.alerts !== 1 ? 's' : ''}
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* ── MITRE ATT&CK tab ────────────────────────────────────────────── */}
      {tab === 'mitre' && (
        <div style={{ flex: 1, overflow: 'auto', padding: 20 }} className="animate-in">
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 16, fontWeight: 700, color: '#e2e8f0' }}>MITRE ATT&CK Heatmap</div>
            <div style={{ fontSize: 12, color: '#64748b' }}>Top attack techniques detected across all pipeline alerts</div>
          </div>

          {mitre.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">⊞</div>
              <span>No MITRE data yet — process alerts to populate this view</span>
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>

              {/* Horizontal bar chart */}
              <div className="glass" style={{ padding: 20 }}>
                <div className="section-title" style={{ marginBottom: 14 }}>Technique Frequency</div>
                <ResponsiveContainer width="100%" height={Math.max(240, mitre.length * 26)}>
                  <BarChart data={mitre} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 100 }}>
                    <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                    <YAxis
                      type="category" dataKey="technique_id"
                      tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}
                      axisLine={false} tickLine={false} width={100}
                    />
                    <Tooltip
                      contentStyle={{ background: '#0d1117', border: '1px solid rgba(139,92,246,0.2)', borderRadius: 6, fontSize: 11, color: '#e2e8f0' }}
                      formatter={(v, _n, p) => [v, p.payload.technique_name || p.payload.technique_id]}
                    />
                    <Bar dataKey="count" name="Detections" radius={[0, 3, 3, 0]}>
                      {mitre.map((_entry, index) => {
                        const intensity = 1 - (index / mitre.length) * 0.6
                        const r = Math.round(139 * intensity)
                        const g = Math.round(92  * intensity)
                        const b = Math.round(246 * intensity)
                        return <Cell key={index} fill={`rgb(${r},${g},${b})`} />
                      })}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {/* Technique cards */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div className="section-title" style={{ marginBottom: 6 }}>Top Techniques</div>
                {mitre.slice(0, 12).map((item, i) => {
                  const maxCount = mitre[0]?.count || 1
                  const pct      = Math.round((item.count / maxCount) * 100)
                  const riskColor = i < 3 ? '#f87171' : i < 7 ? '#fbbf24' : '#38bdf8'
                  return (
                    <div key={item.technique_id} className="glass" style={{ padding: '10px 14px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{
                            fontSize: 10, fontWeight: 700, padding: '2px 6px', borderRadius: 3,
                            background: `${riskColor}15`, color: riskColor,
                            border: `1px solid ${riskColor}30`, fontFamily: 'monospace',
                          }}>
                            {item.technique_id}
                          </span>
                          <span style={{ fontSize: 12, color: '#94a3b8' }}>
                            {item.technique_name !== item.technique_id
                              ? item.technique_name
                              : '—'}
                          </span>
                        </div>
                        <span style={{ fontSize: 13, fontWeight: 800, color: riskColor }}>{item.count}</span>
                      </div>
                      {/* Frequency bar */}
                      <div style={{ height: 3, background: 'rgba(255,255,255,0.05)', borderRadius: 2 }}>
                        <div style={{
                          height: '100%', borderRadius: 2, width: `${pct}%`,
                          background: riskColor, transition: 'width 0.5s ease',
                        }} />
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
