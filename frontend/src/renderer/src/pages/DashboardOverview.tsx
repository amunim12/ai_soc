import { useEffect, useState, useCallback } from 'react'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import MetricsCard from '../components/MetricsCard'
import { api, Metrics, ActivityPoint } from '../lib/api'

export default function DashboardOverview() {
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [activity, setActivity] = useState<ActivityPoint[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const [m, a] = await Promise.all([api.metrics(), api.activity(24)])
      setMetrics(m)
      setActivity(a)
      setError(null)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, 500)
    return () => clearInterval(t)
  }, [load])

  const confidencePct = metrics ? Math.round(metrics.avg_confidence * 100) : 0

  return (
    <div className="page-content animate-in">
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 18, fontWeight: 700, color: '#e2e8f0', marginBottom: 4 }}>
          Security Operations Overview
        </div>
        <div style={{ fontSize: 12, color: '#64748b' }}>
          Real-time pipeline telemetry · auto-refreshes every 5 s
        </div>
      </div>

      {error && (
        <div
          style={{
            padding: '10px 14px',
            background: 'rgba(248,113,113,0.1)',
            border: '1px solid rgba(248,113,113,0.2)',
            borderRadius: 6,
            color: '#f87171',
            fontSize: 12,
            marginBottom: 16,
          }}
        >
          ⚠ Cannot reach backend — {error}
        </div>
      )}

      {/* Metrics grid */}
      {loading && !metrics ? (
        <div className="empty-state">
          <div className="spinner" />
          <span>Loading metrics…</span>
        </div>
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(190px, 1fr))',
            gap: 12,
            marginBottom: 24,
          }}
        >
          <MetricsCard
            label="Total Alerts"
            value={metrics?.total_alerts ?? 0}
            sub="All-time pipeline ingestions"
            icon="📡"
            accentColor="linear-gradient(90deg,#8b5cf6,#38bdf8)"
            delay={0}
          />
          <MetricsCard
            label="Executed Playbooks"
            value={metrics?.executed_playbooks ?? 0}
            sub="SOAR workflows triggered"
            icon="▶"
            accentColor="linear-gradient(90deg,#34d399,#38bdf8)"
            delay={60}
          />
          <MetricsCard
            label="Pending Reviews"
            value={metrics?.pending_reviews ?? 0}
            sub="Awaiting analyst decision"
            icon="⏳"
            accentColor="linear-gradient(90deg,#fbbf24,#f87171)"
            delay={120}
          />
          <MetricsCard
            label="Dropped Alerts"
            value={metrics?.dropped_alerts ?? 0}
            sub="Noise or duplicates filtered"
            icon="🚫"
            accentColor="linear-gradient(90deg,#475569,#64748b)"
            delay={180}
          />
          <MetricsCard
            label="Escalated"
            value={metrics?.escalated_alerts ?? 0}
            sub="Sent to senior analyst"
            icon="⬆"
            accentColor="linear-gradient(90deg,#f87171,#fbbf24)"
            delay={240}
          />
          <MetricsCard
            label="Avg Confidence"
            value={`${confidencePct}%`}
            sub="Playbook generation score"
            icon="◎"
            accentColor={
              confidencePct >= 85
                ? 'linear-gradient(90deg,#34d399,#38bdf8)'
                : 'linear-gradient(90deg,#fbbf24,#f87171)'
            }
            delay={300}
          />
        </div>
      )}

      {/* Activity chart */}
      <div className="glass" style={{ padding: '20px', marginBottom: 24 }}>
        <div className="section-title" style={{ marginBottom: 16 }}>
          24-Hour Alert Activity
        </div>
        {activity.length === 0 ? (
          <div className="empty-state" style={{ padding: '30px 0' }}>
            <div className="empty-state-icon">📊</div>
            <span>No activity data yet</span>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={activity} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="grad-executed" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#34d399" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#34d399" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="grad-dropped" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#f87171" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#f87171" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="hour"
                tick={{ fill: '#64748b', fontSize: 10 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{
                  background: '#0d1117',
                  border: '1px solid rgba(56,189,248,0.2)',
                  borderRadius: 6,
                  fontSize: 11,
                  color: '#e2e8f0',
                }}
              />
              <Area
                type="monotone"
                dataKey="executed"
                stroke="#34d399"
                strokeWidth={1.5}
                fill="url(#grad-executed)"
                name="Executed"
              />
              <Area
                type="monotone"
                dataKey="dropped"
                stroke="#f87171"
                strokeWidth={1.5}
                fill="url(#grad-dropped)"
                name="Dropped"
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>


    </div>
  )
}
