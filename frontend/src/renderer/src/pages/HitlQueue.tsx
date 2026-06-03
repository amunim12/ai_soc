import { useEffect, useState, useCallback } from 'react'
import { api, PendingReview } from '../lib/api'

interface HitlQueueProps {
  onSelectReview: (review: PendingReview) => void
}

function severityFromAlert(alertJson: string): string {
  try {
    return JSON.parse(alertJson)?.severity ?? 'MEDIUM'
  } catch {
    return 'MEDIUM'
  }
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const m = Math.floor(diff / 60_000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

function ruleFromAlert(alertJson: string): string {
  try {
    const a = JSON.parse(alertJson)
    return a.rule_description ?? a.id ?? '—'
  } catch {
    return '—'
  }
}

export default function HitlQueue({ onSelectReview }: HitlQueueProps) {
  const [reviews, setReviews] = useState<PendingReview[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const data = await api.pendingReviews()
      setReviews(data)
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

  const severityClass = (s: string) => s.toLowerCase()

  return (
    <div className="page-content animate-in">
      {/* Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          marginBottom: 20
        }}
      >
        <div>
          <div style={{ fontSize: 18, fontWeight: 700, color: '#e2e8f0', marginBottom: 4 }}>
            HITL Review Queue
          </div>
          <div style={{ fontSize: 12, color: '#64748b' }}>
            Threats requiring human-in-the-loop decision · auto-refreshes every 4 s
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {loading && (
            <div className="spinner" style={{ width: 14, height: 14, borderWidth: 1.5 }} />
          )}
          <span
            style={{
              fontSize: 11,
              fontWeight: 700,
              padding: '4px 10px',
              background: reviews.length > 0 ? 'rgba(248,113,113,0.15)' : 'rgba(52,211,153,0.1)',
              color: reviews.length > 0 ? '#f87171' : '#34d399',
              borderRadius: 99,
              border: `1px solid ${reviews.length > 0 ? 'rgba(248,113,113,0.3)' : 'rgba(52,211,153,0.25)'}`
            }}
          >
            {reviews.length} pending
          </span>
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
            marginBottom: 16
          }}
        >
          ⚠ {error}
        </div>
      )}

      {!loading && reviews.length === 0 && !error && (
        <div className="empty-state">
          <div className="empty-state-icon">✓</div>
          <div style={{ fontWeight: 600, color: '#34d399' }}>Queue is clear</div>
          <div>No threats awaiting review</div>
        </div>
      )}

      <div>
        {reviews.map((review, i) => {
          const severity = severityFromAlert(review.alert_json)
          const rule = ruleFromAlert(review.alert_json)

          return (
            <div
              key={review.review_id}
              className={`threat-card ${severityClass(severity)} animate-in`}
              style={{ animationDelay: `${i * 40}ms` }}
              onClick={() => onSelectReview(review)}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  gap: 12
                }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                    <span className={`badge badge-${severityClass(severity)}`}>{severity}</span>
                    <span
                      style={{
                        fontSize: 10,
                        fontFamily: 'JetBrains Mono, monospace',
                        color: '#64748b'
                      }}
                    >
                      {review.review_id.slice(0, 8)}
                    </span>
                  </div>
                  <div
                    style={{
                      fontSize: 13,
                      fontWeight: 600,
                      color: '#e2e8f0',
                      marginBottom: 4,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap'
                    }}
                  >
                    {rule}
                  </div>
                  <div style={{ fontSize: 11, color: '#64748b' }}>
                    Alert ID:{' '}
                    <span style={{ color: '#94a3b8', fontFamily: 'monospace' }}>
                      {review.alert_id.slice(0, 16)}…
                    </span>
                  </div>
                  {review.reason && (
                    <div style={{ fontSize: 11, color: '#64748b', marginTop: 3 }}>
                      Reason: <span style={{ color: '#94a3b8' }}>{review.reason}</span>
                    </div>
                  )}
                </div>

                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'flex-end',
                    gap: 6,
                    flexShrink: 0
                  }}
                >
                  <div
                    style={{
                      fontSize: 11,
                      fontWeight: 700,
                      padding: '3px 8px',
                      background: 'rgba(139,92,246,0.12)',
                      color: '#c4b5fd',
                      borderRadius: 4,
                      border: '1px solid rgba(139,92,246,0.2)'
                    }}
                  >
                    {Math.round(review.confidence * 100)}% confidence
                  </div>
                  <div style={{ fontSize: 11, color: '#475569' }}>{timeAgo(review.created_at)}</div>
                  <div style={{ fontSize: 11, color: '#38bdf8' }}>Click to review →</div>
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
