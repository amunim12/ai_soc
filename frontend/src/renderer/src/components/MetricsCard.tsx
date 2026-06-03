interface MetricsCardProps {
  label: string
  value: number | string
  sub?: string
  accentColor?: string
  icon?: string
  delay?: number
}

export default function MetricsCard({
  label,
  value,
  sub,
  accentColor = 'linear-gradient(90deg, #8b5cf6, #38bdf8)',
  icon,
  delay = 0
}: MetricsCardProps) {
  return (
    <div
      className="glass glass-hover metric-card animate-in"
      style={{ '--accent-line': accentColor, animationDelay: `${delay}ms` } as React.CSSProperties}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div className="metric-label">{label}</div>
        {icon && <span style={{ fontSize: 18, opacity: 0.5 }}>{icon}</span>}
      </div>
      <div className="metric-value">{value}</div>
      {sub && <div className="metric-sub">{sub}</div>}
    </div>
  )
}
