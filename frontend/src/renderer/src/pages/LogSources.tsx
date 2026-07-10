import { useEffect, useState, useCallback } from 'react'
import {
  api,
  LogSource,
  LogSourceCreate,
  LogSourceUpdate,
  EnrollmentInstructions,
  SoarTestResult,
  LogSourceLiveStatus,
  SourceType,
  OsType
} from '../lib/api'

// ── Status badge ─────────────────────────────────────────────────────────────

const STATUS_COLORS: Record<string, { bg: string; text: string; label: string }> = {
  active: { bg: '#14532d', text: '#4ade80', label: 'Active' },
  disconnected: { bg: '#7f1d1d', text: '#f87171', label: 'Disconnected' },
  never_connected: { bg: '#1c1917', text: '#78716c', label: 'Never Connected' },
  pending: { bg: '#422006', text: '#fbbf24', label: 'Pending' },
  unknown: { bg: '#1e293b', text: '#64748b', label: 'Unknown' }
}

function StatusBadge({ status }: { status: string }) {
  const c = STATUS_COLORS[status] ?? STATUS_COLORS.unknown
  return (
    <span
      style={{
        background: c.bg,
        color: c.text,
        padding: '2px 8px',
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.05em'
      }}
    >
      {c.label}
    </span>
  )
}

// ── Add / Edit modal ─────────────────────────────────────────────────────────

const SOURCE_TYPES: SourceType[] = ['agent', 'syslog', 'windows_event', 'api', 'network', 'cloud']
const OS_TYPES: OsType[] = ['linux', 'windows', 'macos', 'network', 'cloud']
const AVAILABLE_SOAR_ACTIONS = [
  'block_ip',
  'isolate_host',
  'disable_user',
  'kill_process',
  'collect_forensics',
  'restart_service',
  'run_vulnerability_scan'
]

interface ModalProps {
  initial?: LogSource
  onSave: (values: LogSourceCreate | LogSourceUpdate) => Promise<void>
  onClose: () => void
}

function LogSourceModal({ initial, onSave, onClose }: ModalProps) {
  const [name, setName] = useState(initial?.name ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [sourceType, setSourceType] = useState<SourceType>(initial?.source_type ?? 'agent')
  const [host, setHost] = useState(initial?.host ?? '')
  const [osType, setOsType] = useState<OsType | ''>(initial?.os_type ?? '')
  const [soarEnabled, setSoarEnabled] = useState(initial?.soar_enabled ?? false)
  const [soarActions, setSoarActions] = useState<string[]>(initial?.soar_actions ?? [])
  const [soarTargetLabel, setSoarTargetLabel] = useState(initial?.soar_target_label ?? '')
  const [tags, setTags] = useState(initial?.tags?.join(', ') ?? '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  function toggleAction(a: string) {
    setSoarActions((prev) => (prev.includes(a) ? prev.filter((x) => x !== a) : [...prev, a]))
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim() || !host.trim()) {
      setError('Name and host are required.')
      return
    }
    setSaving(true)
    setError('')
    try {
      await onSave({
        name: name.trim(),
        description: description.trim(),
        source_type: sourceType,
        host: host.trim(),
        os_type: osType || null,
        soar_enabled: soarEnabled,
        soar_actions: soarActions,
        soar_target_label: soarTargetLabel.trim() || null,
        tags: tags
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean)
      })
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.7)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 50
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        style={{
          background: '#0f172a',
          border: '1px solid #1e293b',
          borderRadius: 10,
          width: 560,
          maxHeight: '90vh',
          overflowY: 'auto',
          padding: 28
        }}
      >
        <h2 style={{ margin: '0 0 20px', fontSize: 16, color: '#e2e8f0' }}>
          {initial ? 'Edit Log Source' : 'Add Log Source'}
        </h2>

        <form onSubmit={handleSubmit}>
          {/* Name + Host */}
          <div
            style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 }}
          >
            <label style={labelStyle}>
              Name *
              <input
                style={inputStyle}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="web-server-01"
              />
            </label>
            <label style={labelStyle}>
              Host / IP *
              <input
                style={inputStyle}
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="192.168.1.50"
              />
            </label>
          </div>

          {/* Description */}
          <label style={{ ...labelStyle, marginBottom: 14 }}>
            Description
            <input
              style={inputStyle}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional description"
            />
          </label>

          {/* Source type + OS */}
          <div
            style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 }}
          >
            <label style={labelStyle}>
              Source Type
              <select
                style={inputStyle}
                value={sourceType}
                onChange={(e) => setSourceType(e.target.value as SourceType)}
              >
                {SOURCE_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </label>
            <label style={labelStyle}>
              OS Type
              <select
                style={inputStyle}
                value={osType}
                onChange={(e) => setOsType(e.target.value as OsType | '')}
              >
                <option value="">— auto —</option>
                {OS_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {/* Tags */}
          <label style={{ ...labelStyle, marginBottom: 14 }}>
            Tags (comma-separated)
            <input
              style={inputStyle}
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="prod, linux, web"
            />
          </label>

          {/* SOAR */}
          <div
            style={{
              background: '#0d1117',
              border: '1px solid #1e293b',
              borderRadius: 7,
              padding: 14,
              marginBottom: 14
            }}
          >
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                cursor: 'pointer',
                marginBottom: soarEnabled ? 12 : 0
              }}
            >
              <input
                type="checkbox"
                checked={soarEnabled}
                onChange={(e) => setSoarEnabled(e.target.checked)}
              />
              <span style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>
                Enable SOAR Integration
              </span>
            </label>

            {soarEnabled && (
              <>
                <label style={{ ...labelStyle, marginBottom: 10 }}>
                  Shuffle Asset Label
                  <input
                    style={inputStyle}
                    value={soarTargetLabel}
                    onChange={(e) => setSoarTargetLabel(e.target.value)}
                    placeholder="Matches asset label in Shuffle workflows"
                  />
                </label>
                <div style={{ color: '#94a3b8', fontSize: 11, marginBottom: 6 }}>
                  Allowed SOAR actions:
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {AVAILABLE_SOAR_ACTIONS.map((a) => (
                    <button
                      key={a}
                      type="button"
                      onClick={() => toggleAction(a)}
                      style={{
                        padding: '3px 10px',
                        borderRadius: 4,
                        fontSize: 11,
                        cursor: 'pointer',
                        border: soarActions.includes(a) ? '1px solid #8b5cf6' : '1px solid #334155',
                        background: soarActions.includes(a) ? '#2e1065' : '#1e293b',
                        color: soarActions.includes(a) ? '#c4b5fd' : '#64748b'
                      }}
                    >
                      {a}
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>

          {error && <div style={{ color: '#f87171', fontSize: 12, marginBottom: 10 }}>{error}</div>}

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
            <button type="button" onClick={onClose} style={btnSecondary}>
              Cancel
            </button>
            <button type="submit" disabled={saving} style={btnPrimary}>
              {saving ? 'Saving…' : initial ? 'Save Changes' : 'Add Source'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Enrollment drawer ─────────────────────────────────────────────────────────

function EnrollDrawer({
  instructions,
  onClose
}: {
  instructions: EnrollmentInstructions
  onClose: () => void
}) {
  const [copied, setCopied] = useState(false)
  const allCmds = instructions.install_commands.join('\n')

  function copy() {
    navigator.clipboard.writeText(allCmds).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.7)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 50
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        style={{
          background: '#0f172a',
          border: '1px solid #1e293b',
          borderRadius: 10,
          width: 640,
          maxHeight: '90vh',
          overflowY: 'auto',
          padding: 28
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: 18
          }}
        >
          <h2 style={{ margin: 0, fontSize: 16, color: '#e2e8f0' }}>Wazuh Agent Enrollment</h2>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              color: '#64748b',
              fontSize: 18,
              cursor: 'pointer'
            }}
          >
            ✕
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
          <div style={infoBox}>
            <div style={infoLabel}>Manager IP</div>
            <div style={infoValue}>{instructions.wazuh_manager_ip}</div>
          </div>
          <div style={infoBox}>
            <div style={infoLabel}>Enrollment Key</div>
            <div
              style={{
                ...infoValue,
                fontFamily: 'monospace',
                fontSize: 11,
                wordBreak: 'break-all'
              }}
            >
              {instructions.enrollment_key ?? '— will be auto-generated on agent start —'}
            </div>
          </div>
        </div>

        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: 8
          }}
        >
          <div style={{ color: '#94a3b8', fontSize: 12 }}>Install commands</div>
          <button onClick={copy} style={btnSecondary}>
            {copied ? '✓ Copied' : 'Copy all'}
          </button>
        </div>
        <pre
          style={{
            background: '#020617',
            border: '1px solid #0f172a',
            borderRadius: 6,
            padding: 14,
            fontSize: 11,
            color: '#94a3b8',
            overflowX: 'auto',
            margin: '0 0 14px',
            lineHeight: 1.6,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all'
          }}
        >
          {allCmds}
        </pre>

        <div
          style={{
            background: '#0d1117',
            border: '1px solid #1e293b',
            borderRadius: 6,
            padding: 12
          }}
        >
          <div style={{ color: '#94a3b8', fontSize: 12, whiteSpace: 'pre-wrap' }}>
            {instructions.notes}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── SOAR test result toast ────────────────────────────────────────────────────

function SoarResultBanner({ result, onClose }: { result: SoarTestResult; onClose: () => void }) {
  return (
    <div
      style={{
        position: 'fixed',
        bottom: 24,
        right: 24,
        zIndex: 60,
        background: result.reachable ? '#14532d' : '#7f1d1d',
        border: `1px solid ${result.reachable ? '#166534' : '#991b1b'}`,
        color: result.reachable ? '#4ade80' : '#f87171',
        borderRadius: 8,
        padding: '12px 16px',
        maxWidth: 360,
        display: 'flex',
        alignItems: 'flex-start',
        gap: 10
      }}
    >
      <span style={{ fontSize: 16 }}>{result.reachable ? '✓' : '✗'}</span>
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 600, fontSize: 13 }}>
          SOAR Test {result.reachable ? 'Passed' : 'Failed'}
        </div>
        <div style={{ fontSize: 12, marginTop: 3, opacity: 0.85 }}>{result.message}</div>
      </div>
      <button
        onClick={onClose}
        style={{
          background: 'none',
          border: 'none',
          color: 'inherit',
          cursor: 'pointer',
          fontSize: 14
        }}
      >
        ✕
      </button>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

interface LogSourcesProps {
  onBack: () => void
}

export default function LogSources({ onBack }: LogSourcesProps) {
  const [sources, setSources] = useState<LogSource[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [modalOpen, setModalOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<LogSource | null>(null)

  const [enrollTarget, setEnrollTarget] = useState<EnrollmentInstructions | null>(null)
  const [enrollLoading, setEnrollLoading] = useState<string | null>(null)

  const [statusLoading, setStatusLoading] = useState<string | null>(null)
  const [liveStatus, setLiveStatus] = useState<Record<string, LogSourceLiveStatus>>({})

  const [soarTesting, setSoarTesting] = useState<string | null>(null)
  const [soarResult, setSoarResult] = useState<SoarTestResult | null>(null)

  const [deleteConfirm, setDeleteConfirm] = useState<LogSource | null>(null)
  const [deleteLoading, setDeleteLoading] = useState(false)

  const load = useCallback(async () => {
    try {
      const data = await api.logSources()
      setSources(data)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load log sources')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  async function handleSave(values: LogSourceCreate | LogSourceUpdate) {
    if (editTarget) {
      await api.logSourceUpdate(editTarget.id, values as LogSourceUpdate)
    } else {
      await api.logSourceCreate(values as LogSourceCreate)
    }
    setModalOpen(false)
    setEditTarget(null)
    await load()
  }

  async function handleDelete() {
    if (!deleteConfirm) return
    setDeleteLoading(true)
    try {
      await api.logSourceDelete(deleteConfirm.id)
      setDeleteConfirm(null)
      await load()
    } finally {
      setDeleteLoading(false)
    }
  }

  async function handleRefreshStatus(src: LogSource) {
    setStatusLoading(src.id)
    try {
      const status = await api.logSourceStatus(src.id)
      setLiveStatus((prev) => ({ ...prev, [src.id]: status }))
      await load()
    } finally {
      setStatusLoading(null)
    }
  }

  async function handleEnroll(src: LogSource) {
    setEnrollLoading(src.id)
    try {
      const instructions = await api.logSourceEnroll(src.id)
      setEnrollTarget(instructions)
    } finally {
      setEnrollLoading(null)
    }
  }

  async function handleTestSoar(src: LogSource) {
    setSoarTesting(src.id)
    try {
      const result = await api.logSourceTestSoar(src.id)
      setSoarResult(result)
    } finally {
      setSoarTesting(null)
    }
  }

  return (
    <div
      style={{ padding: '24px 28px', minHeight: '100vh', background: '#020617', color: '#e2e8f0' }}
    >
      <style>{pageStyles}</style>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
        <button
          onClick={onBack}
          style={{
            background: 'none',
            border: 'none',
            color: '#64748b',
            cursor: 'pointer',
            fontSize: 18,
            lineHeight: 1
          }}
        >
          ←
        </button>
        <div>
          <h1 style={{ margin: 0, fontSize: 20, fontWeight: 700 }}>Log Sources</h1>
          <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>
            Manage Wazuh agents and SOAR integration targets
          </div>
        </div>
        <div style={{ marginLeft: 'auto' }}>
          <button
            onClick={() => {
              setEditTarget(null)
              setModalOpen(true)
            }}
            style={btnPrimary}
          >
            + Add Source
          </button>
        </div>
      </div>

      {error && (
        <div
          style={{
            background: '#7f1d1d',
            border: '1px solid #991b1b',
            borderRadius: 6,
            padding: '10px 14px',
            marginBottom: 16,
            color: '#fca5a5',
            fontSize: 13
          }}
        >
          {error}
        </div>
      )}

      {loading ? (
        <div style={{ color: '#475569', padding: 40, textAlign: 'center' }}>Loading…</div>
      ) : sources.length === 0 ? (
        <div
          style={{
            border: '1px dashed #1e293b',
            borderRadius: 8,
            padding: '60px 40px',
            textAlign: 'center',
            color: '#475569'
          }}
        >
          <div style={{ fontSize: 32, marginBottom: 12 }}>⊕</div>
          <div style={{ fontSize: 15, fontWeight: 600, color: '#64748b', marginBottom: 6 }}>
            No log sources configured
          </div>
          <div style={{ fontSize: 13 }}>
            Add a log source to connect it to Wazuh SIEM and Shuffle SOAR.
          </div>
        </div>
      ) : (
        <div style={{ border: '1px solid #1e293b', borderRadius: 8, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ background: '#0d1117', borderBottom: '1px solid #1e293b' }}>
                {['Name', 'Host', 'Type', 'OS', 'Wazuh Status', 'SOAR', 'Actions'].map((h) => (
                  <th
                    key={h}
                    style={{
                      padding: '10px 14px',
                      textAlign: 'left',
                      color: '#64748b',
                      fontWeight: 600,
                      fontSize: 11,
                      textTransform: 'uppercase',
                      letterSpacing: '0.06em'
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sources.map((src, i) => {
                const live = liveStatus[src.id]
                const displayStatus = live?.wazuh_status ?? src.wazuh_status
                return (
                  <tr
                    key={src.id}
                    style={{
                      borderBottom: i < sources.length - 1 ? '1px solid #0f172a' : 'none',
                      background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)'
                    }}
                  >
                    <td style={td}>
                      <div style={{ fontWeight: 600, color: '#e2e8f0' }}>{src.name}</div>
                      {src.description && (
                        <div style={{ fontSize: 11, color: '#475569', marginTop: 1 }}>
                          {src.description}
                        </div>
                      )}
                      {src.tags.length > 0 && (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
                          {src.tags.map((t) => (
                            <span
                              key={t}
                              style={{
                                background: '#1e293b',
                                color: '#94a3b8',
                                padding: '1px 6px',
                                borderRadius: 3,
                                fontSize: 10
                              }}
                            >
                              {t}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td style={{ ...td, fontFamily: 'monospace', fontSize: 12 }}>{src.host}</td>
                    <td style={td}>{src.source_type}</td>
                    <td style={{ ...td, color: '#94a3b8' }}>{src.os_type ?? '—'}</td>
                    <td style={td}>
                      <StatusBadge status={displayStatus} />
                      {src.wazuh_agent_id && (
                        <div
                          style={{
                            fontSize: 10,
                            color: '#475569',
                            marginTop: 3,
                            fontFamily: 'monospace'
                          }}
                        >
                          id: {src.wazuh_agent_id}
                        </div>
                      )}
                    </td>
                    <td style={td}>
                      {src.soar_enabled ? (
                        <div>
                          <span style={{ color: '#a78bfa', fontSize: 11, fontWeight: 600 }}>
                            Enabled
                          </span>
                          {src.soar_actions.length > 0 && (
                            <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>
                              {src.soar_actions.join(', ')}
                            </div>
                          )}
                        </div>
                      ) : (
                        <span style={{ color: '#334155', fontSize: 11 }}>Disabled</span>
                      )}
                    </td>
                    <td style={{ ...td, whiteSpace: 'nowrap' }}>
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        <button
                          onClick={() => handleRefreshStatus(src)}
                          disabled={statusLoading === src.id}
                          style={btnAction}
                          title="Refresh Wazuh status"
                        >
                          {statusLoading === src.id ? '…' : '↻ Status'}
                        </button>
                        <button
                          onClick={() => handleEnroll(src)}
                          disabled={enrollLoading === src.id}
                          style={btnAction}
                          title="Show enrollment instructions"
                        >
                          {enrollLoading === src.id ? '…' : '⤓ Enroll'}
                        </button>
                        {src.soar_enabled && (
                          <button
                            onClick={() => handleTestSoar(src)}
                            disabled={soarTesting === src.id}
                            style={{ ...btnAction, color: '#a78bfa', borderColor: '#4c1d95' }}
                            title="Test Shuffle SOAR connection"
                          >
                            {soarTesting === src.id ? '…' : '▷ SOAR'}
                          </button>
                        )}
                        <button
                          onClick={() => {
                            setEditTarget(src)
                            setModalOpen(true)
                          }}
                          style={btnAction}
                          title="Edit"
                        >
                          ✎
                        </button>
                        <button
                          onClick={() => setDeleteConfirm(src)}
                          style={{ ...btnAction, color: '#f87171', borderColor: '#7f1d1d' }}
                          title="Delete"
                        >
                          ✕
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Modals */}
      {modalOpen && (
        <LogSourceModal
          initial={editTarget ?? undefined}
          onSave={handleSave}
          onClose={() => {
            setModalOpen(false)
            setEditTarget(null)
          }}
        />
      )}

      {enrollTarget && (
        <EnrollDrawer instructions={enrollTarget} onClose={() => setEnrollTarget(null)} />
      )}

      {soarResult && <SoarResultBanner result={soarResult} onClose={() => setSoarResult(null)} />}

      {/* Delete confirmation */}
      {deleteConfirm && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 50
          }}
        >
          <div
            style={{
              background: '#0f172a',
              border: '1px solid #1e293b',
              borderRadius: 10,
              padding: 28,
              width: 380
            }}
          >
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 10 }}>
              Delete log source?
            </div>
            <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 20 }}>
              <strong style={{ color: '#e2e8f0' }}>{deleteConfirm.name}</strong> (
              {deleteConfirm.host}) will be removed. The Wazuh agent on the target host will not be
              uninstalled automatically.
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button onClick={() => setDeleteConfirm(null)} style={btnSecondary}>
                Cancel
              </button>
              <button
                onClick={handleDelete}
                disabled={deleteLoading}
                style={{ ...btnPrimary, background: '#7f1d1d', borderColor: '#991b1b' }}
              >
                {deleteLoading ? 'Deleting…' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Shared styles ─────────────────────────────────────────────────────────────

const labelStyle: React.CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  gap: 5,
  fontSize: 12,
  color: '#94a3b8',
  fontWeight: 500
}

const inputStyle: React.CSSProperties = {
  background: '#0d1117',
  border: '1px solid #1e293b',
  borderRadius: 5,
  padding: '7px 10px',
  color: '#e2e8f0',
  fontSize: 13,
  outline: 'none'
}

const btnPrimary: React.CSSProperties = {
  background: 'linear-gradient(135deg, #4f46e5, #7c3aed)',
  border: '1px solid #4338ca',
  color: '#fff',
  padding: '8px 16px',
  borderRadius: 6,
  cursor: 'pointer',
  fontSize: 13,
  fontWeight: 600
}

const btnSecondary: React.CSSProperties = {
  background: '#1e293b',
  border: '1px solid #334155',
  color: '#94a3b8',
  padding: '7px 14px',
  borderRadius: 6,
  cursor: 'pointer',
  fontSize: 12
}

const btnAction: React.CSSProperties = {
  background: '#0d1117',
  border: '1px solid #1e293b',
  color: '#64748b',
  padding: '4px 9px',
  borderRadius: 4,
  cursor: 'pointer',
  fontSize: 11
}

const td: React.CSSProperties = { padding: '10px 14px', verticalAlign: 'top' }

const infoBox: React.CSSProperties = {
  background: '#0d1117',
  border: '1px solid #1e293b',
  borderRadius: 6,
  padding: '10px 12px'
}
const infoLabel: React.CSSProperties = {
  fontSize: 10,
  color: '#475569',
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
  marginBottom: 4
}
const infoValue: React.CSSProperties = { fontSize: 13, color: '#e2e8f0', fontWeight: 500 }

const pageStyles = `
  input, select { color-scheme: dark; }
  input:focus, select:focus { border-color: #4f46e5 !important; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
`
