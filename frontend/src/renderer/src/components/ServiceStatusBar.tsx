import { useEffect, useState } from 'react'
import type { ServiceStatus } from '../../../preload/index.d'

const STATUS_COLOR: Record<ServiceStatus, string> = {
  running: '#34d399',
  starting: '#fbbf24',
  stopped: '#64748b',
  error: '#f87171'
}

const STATUS_LABEL: Record<ServiceStatus, string> = {
  running: 'Services running',
  starting: 'Services starting…',
  stopped: 'Services stopped',
  error: 'Service error'
}

export function ServiceStatusBar() {
  const [status, setStatus] = useState<ServiceStatus>('stopped')
  const [message, setMessage] = useState('')

  useEffect(() => {
    window.backend.getStatus().then((s) => setStatus(s as ServiceStatus))

    const unsubscribe = window.backend.onStatusChanged((state) => {
      setStatus(state.status as ServiceStatus)
      setMessage(state.message)
    })
    return unsubscribe
  }, [])

  const color = STATUS_COLOR[status]
  const label = STATUS_LABEL[status]

  return (
    <div
      style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#64748b' }}
      title={message || label}
    >
      <span
        style={{
          width: 7,
          height: 7,
          borderRadius: '50%',
          background: color,
          display: 'inline-block',
          boxShadow: status === 'running' ? `0 0 6px ${color}` : 'none'
        }}
      />
      <span style={{ color }}>{label}</span>
    </div>
  )
}
