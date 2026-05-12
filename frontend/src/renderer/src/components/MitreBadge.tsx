interface MitreBadgeProps {
  technique: string
}

export default function MitreBadge({ technique }: MitreBadgeProps) {
  return (
    <span className="mitre-badge" title={`MITRE ATT&CK Technique ${technique}`}>
      ⊕ {technique}
    </span>
  )
}
