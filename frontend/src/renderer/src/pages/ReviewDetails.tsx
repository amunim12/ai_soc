import { useState } from 'react'
import ThreatGraph from '../components/ThreatGraph'
import MitreBadge from '../components/MitreBadge'
import { api, PendingReview } from '../lib/api'

interface ReviewDetailsProps {
  review: PendingReview
  onBack: () => void
  onDecisionMade: () => void
}

interface PlaybookStep {
  step_id: string
  action_type: string
  description: string
  target?: string
  mitre_technique?: string
  requires_confirmation?: boolean
}

interface PlaybookPhase {
  phase_name: string
  steps: PlaybookStep[]
}

interface Playbook {
  title?: string
  summary?: string
  confidence_score?: number
  estimated_duration_minutes?: number
  phases?: Record<string, PlaybookPhase>
}

type Action = 'APPROVE' | 'EDIT' | 'REJECT' | 'ESCALATE'
type PlaybookTab = 'visual' | 'yaml'

const PHASE_COLORS: Record<string, string> = {
  containment: '#f87171',
  eradication: '#fbbf24',
  recovery: '#34d399'
}
const PHASE_ICONS: Record<string, string> = {
  containment: '🔒',
  eradication: '🗑',
  recovery: '♻'
}

function playbookToYaml(_pb: Playbook, raw: string): string {
  // Return prettified raw JSON as fallback YAML-like view
  try {
    const obj = JSON.parse(raw)
    // produce a readable YAML-like text
    const lines: string[] = []
    lines.push(`title: ${obj.title ?? ''}`)
    lines.push(`summary: ${obj.summary ?? ''}`)
    lines.push(`confidence_score: ${obj.confidence_score ?? 0}`)
    lines.push(`estimated_duration_minutes: ${obj.estimated_duration_minutes ?? 30}`)
    for (const [pName, phase] of Object.entries(obj.phases ?? {})) {
      lines.push(`\n${pName}:`)
      lines.push(`  steps:`)
      for (const s of (phase as PlaybookPhase).steps) {
        lines.push(`    - step_id: ${s.step_id}`)
        lines.push(`      action_type: ${s.action_type}`)
        lines.push(`      description: "${s.description}"`)
        if (s.target) lines.push(`      target: ${s.target}`)
        if (s.mitre_technique) lines.push(`      mitre_technique: ${s.mitre_technique}`)
        if (s.requires_confirmation) lines.push(`      requires_confirmation: true`)
      }
    }
    return lines.join('\n')
  } catch {
    return raw
  }
}

export default function ReviewDetails({ review, onBack, onDecisionMade }: ReviewDetailsProps) {
  const [analystId, setAnalystId] = useState('analyst-1')
  const [notes, setNotes] = useState('')
  const [submitting, setSubmitting] = useState<Action | null>(null)
  const [result, setResult] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [playbookTab, setPlaybookTab] = useState<PlaybookTab>('visual')
  const [yamlText, setYamlText] = useState<string | null>(null)

  let alert: Record<string, unknown> = {}
  let playbook: Playbook = {}

  try {
    alert = JSON.parse(review.alert_json)
  } catch {
    /* empty */
  }
  try {
    playbook = JSON.parse(review.playbook_json)
  } catch {
    /* empty */
  }

  const phases = Object.entries(playbook.phases ?? {})
  const uniqueMitre = [
    ...new Set(
      phases.flatMap(([, p]) =>
        p.steps.filter((s) => s.mitre_technique).map((s) => s.mitre_technique as string)
      )
    )
  ]

  function switchToYaml() {
    if (yamlText === null) setYamlText(playbookToYaml(playbook, review.playbook_json))
    setPlaybookTab('yaml')
  }

  async function submit(action: Action) {
    setSubmitting(action)
    setError(null)
    try {
      const res = await api.submitDecision(review.review_id, {
        action,
        analyst_id: analystId || 'analyst-1',
        notes,
        // send edited YAML when action=EDIT
        ...(action === 'EDIT' && yamlText ? { final_playbook_yaml: yamlText } : {})
      })
      setResult(res.message)
      setTimeout(onDecisionMade, 1500)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setSubmitting(null)
    }
  }

  return (
    <div className="page-content animate-slide">
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
        <button className="btn btn-ghost" onClick={onBack}>
          ← Back
        </button>
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, color: '#e2e8f0' }}>
            Threat Investigation
          </div>
          <div style={{ fontSize: 11, fontFamily: 'monospace', color: '#64748b' }}>
            {review.review_id}
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
        {/* ── Left: Alert + Graph ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div className="glass" style={{ padding: 16 }}>
            <div className="section-title">Alert Details</div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: '6px 12px',
                fontSize: 12
              }}
            >
              {[
                ['Alert ID', (alert.id as string)?.slice(0, 16) + '…'],
                ['Severity', alert.severity as string],
                ['Category', alert.alert_category as string],
                ['Agent', (alert.agent_name ?? alert.agent_id) as string],
                ['Source IP', (alert.source_ip ?? '—') as string],
                ['Destination', (alert.destination_ip ?? '—') as string],
                ['User', (alert.user ?? '—') as string],
                ['Rule', (alert.rule_description as string)?.slice(0, 40)]
              ].map(([k, v]) => (
                <div key={k}>
                  <div
                    style={{
                      color: '#64748b',
                      fontSize: 10,
                      textTransform: 'uppercase',
                      letterSpacing: '0.06em'
                    }}
                  >
                    {k}
                  </div>
                  <div style={{ color: '#e2e8f0', marginTop: 1 }}>{v ?? '—'}</div>
                </div>
              ))}
            </div>
            {uniqueMitre.length > 0 && (
              <div style={{ marginTop: 12, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {uniqueMitre.map((t) => (
                  <MitreBadge key={t} technique={t} />
                ))}
              </div>
            )}
          </div>

          <div className="glass" style={{ padding: 16 }}>
            <div className="section-title">Threat Graph</div>
            <ThreatGraph
              alert={{
                id: alert.id as string,
                agent_id: alert.agent_id as string,
                agent_name: alert.agent_name as string,
                source_ip: alert.source_ip as string,
                destination_ip: alert.destination_ip as string,
                user: alert.user as string,
                rule_description: alert.rule_description as string,
                severity: alert.severity as string
              }}
            />
          </div>
        </div>

        {/* ── Right: Playbook + Decision ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Playbook header + tab switcher */}
          <div className="glass" style={{ padding: 16 }}>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'flex-start',
                marginBottom: 8
              }}
            >
              <div className="section-title" style={{ marginBottom: 0 }}>
                Generated Playbook
              </div>
              <div style={{ display: 'flex', gap: 4 }}>
                {(['visual', 'yaml'] as PlaybookTab[]).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => (tab === 'yaml' ? switchToYaml() : setPlaybookTab('visual'))}
                    style={{
                      padding: '3px 10px',
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 600,
                      cursor: 'pointer',
                      border: '1px solid transparent',
                      background: playbookTab === tab ? 'rgba(139,92,246,0.2)' : 'transparent',
                      color: playbookTab === tab ? '#c4b5fd' : '#64748b',
                      borderColor:
                        playbookTab === tab ? 'rgba(139,92,246,0.4)' : 'rgba(255,255,255,0.06)',
                      transition: 'all 0.15s'
                    }}
                  >
                    {tab === 'visual' ? '◫ Visual' : '</> YAML'}
                  </button>
                ))}
              </div>
            </div>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0', marginBottom: 4 }}>
              {playbook.title ?? 'Incident Response Playbook'}
            </div>
            {playbook.summary && (
              <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 8 }}>
                {playbook.summary}
              </div>
            )}
            <div style={{ display: 'flex', gap: 8 }}>
              <span style={{ fontSize: 11, color: '#64748b' }}>
                Confidence:{' '}
                <span
                  style={{
                    fontWeight: 700,
                    color: (playbook.confidence_score ?? 0) >= 0.85 ? '#34d399' : '#fbbf24'
                  }}
                >
                  {Math.round((playbook.confidence_score ?? 0) * 100)}%
                </span>
              </span>
              <span style={{ color: '#334155' }}>·</span>
              <span style={{ fontSize: 11, color: '#64748b' }}>
                Est:{' '}
                <span style={{ color: '#94a3b8', fontWeight: 600 }}>
                  {playbook.estimated_duration_minutes ?? '?'} min
                </span>
              </span>
            </div>
          </div>

          {/* Playbook body — visual or YAML editor */}
          <div className="glass" style={{ overflow: 'hidden', flex: 1 }}>
            {playbookTab === 'yaml' ? (
              <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
                <div
                  style={{
                    padding: '8px 14px',
                    background: 'rgba(139,92,246,0.08)',
                    borderBottom: '1px solid rgba(139,92,246,0.15)',
                    fontSize: 11,
                    color: '#c4b5fd',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                  }}
                >
                  <span>
                    ✎ Live YAML Editor — submit with action &quot;Edit&quot; to apply changes
                  </span>
                  <button
                    className="btn btn-ghost"
                    style={{ fontSize: 10, padding: '2px 8px' }}
                    onClick={() => {
                      setYamlText(playbookToYaml(playbook, review.playbook_json))
                    }}
                  >
                    Reset
                  </button>
                </div>
                <textarea
                  value={yamlText ?? ''}
                  onChange={(e) => setYamlText(e.target.value)}
                  style={{
                    flex: 1,
                    background: 'rgba(0,0,0,0.35)',
                    border: 'none',
                    color: '#94a3b8',
                    fontFamily: 'JetBrains Mono, Fira Code, monospace',
                    fontSize: 12,
                    lineHeight: 1.6,
                    padding: 14,
                    resize: 'none',
                    outline: 'none',
                    minHeight: 260
                  }}
                  spellCheck={false}
                />
              </div>
            ) : phases.length === 0 ? (
              <div className="empty-state" style={{ padding: '30px 0' }}>
                <div className="empty-state-icon">📋</div>
                <span>No playbook phases</span>
              </div>
            ) : (
              phases.map(([phaseName, phase]) => (
                <div key={phaseName}>
                  <div
                    className="phase-header"
                    style={{ color: PHASE_COLORS[phaseName] ?? '#94a3b8' }}
                  >
                    <span>{PHASE_ICONS[phaseName] ?? '◈'}</span>
                    <span>{phase.phase_name ?? phaseName}</span>
                    <span
                      style={{
                        marginLeft: 'auto',
                        fontSize: 10,
                        color: '#475569',
                        fontWeight: 400,
                        textTransform: 'none',
                        letterSpacing: 0
                      }}
                    >
                      {phase.steps.length} step{phase.steps.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                  {phase.steps.map((step) => (
                    <div key={step.step_id} className="playbook-step">
                      <span className="step-action">{step.action_type}</span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 12, color: '#e2e8f0', marginBottom: 3 }}>
                          {step.description}
                        </div>
                        <div
                          style={{
                            display: 'flex',
                            flexWrap: 'wrap',
                            gap: 6,
                            alignItems: 'center'
                          }}
                        >
                          {step.target && (
                            <span
                              style={{ fontSize: 10, fontFamily: 'monospace', color: '#64748b' }}
                            >
                              target: <span style={{ color: '#94a3b8' }}>{step.target}</span>
                            </span>
                          )}
                          {step.mitre_technique && <MitreBadge technique={step.mitre_technique} />}
                          {step.requires_confirmation && (
                            <span
                              style={{
                                fontSize: 10,
                                padding: '1px 5px',
                                background: 'rgba(251,191,36,0.12)',
                                color: '#fbbf24',
                                borderRadius: 3,
                                border: '1px solid rgba(251,191,36,0.2)'
                              }}
                            >
                              ⚠ confirm
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ))
            )}
          </div>

          {/* Decision panel */}
          <div className="glass" style={{ padding: 16 }}>
            <div className="section-title">Analyst Decision</div>
            {result ? (
              <div
                style={{
                  padding: '12px 14px',
                  background: 'rgba(52,211,153,0.1)',
                  border: '1px solid rgba(52,211,153,0.25)',
                  borderRadius: 6,
                  color: '#34d399',
                  fontSize: 12
                }}
              >
                ✓ {result}
              </div>
            ) : (
              <>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 12 }}>
                  <input
                    className="input"
                    placeholder="Analyst ID"
                    value={analystId}
                    onChange={(e) => setAnalystId(e.target.value)}
                  />
                  <textarea
                    className="input"
                    placeholder="Notes (optional)"
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    rows={2}
                  />
                </div>
                {error && (
                  <div
                    style={{
                      padding: '8px 12px',
                      background: 'rgba(248,113,113,0.1)',
                      border: '1px solid rgba(248,113,113,0.2)',
                      borderRadius: 6,
                      color: '#f87171',
                      fontSize: 11,
                      marginBottom: 10
                    }}
                  >
                    {error}
                  </div>
                )}
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button
                    className="btn btn-approve"
                    onClick={() => submit('APPROVE')}
                    disabled={submitting !== null}
                    style={{ flex: 1, justifyContent: 'center' }}
                  >
                    {submitting === 'APPROVE' ? <span className="spinner" /> : '✓'} Approve
                  </button>
                  {playbookTab === 'yaml' && (
                    <button
                      className="btn btn-primary"
                      onClick={() => submit('EDIT')}
                      disabled={submitting !== null}
                      style={{ flex: 1, justifyContent: 'center' }}
                    >
                      {submitting === 'EDIT' ? <span className="spinner" /> : '✎'} Submit Edit
                    </button>
                  )}
                  <button
                    className="btn btn-escalate"
                    onClick={() => submit('ESCALATE')}
                    disabled={submitting !== null}
                    style={{ flex: 1, justifyContent: 'center' }}
                  >
                    {submitting === 'ESCALATE' ? <span className="spinner" /> : '⬆'} Escalate
                  </button>
                  <button
                    className="btn btn-reject"
                    onClick={() => submit('REJECT')}
                    disabled={submitting !== null}
                    style={{ flex: 1, justifyContent: 'center' }}
                  >
                    {submitting === 'REJECT' ? <span className="spinner" /> : '✕'} Reject
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
