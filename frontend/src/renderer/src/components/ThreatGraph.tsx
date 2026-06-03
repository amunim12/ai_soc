import { useEffect, useRef } from 'react'
import cytoscape from 'cytoscape'

interface AlertData {
  id: string
  agent_id?: string
  agent_name?: string
  source_ip?: string
  destination_ip?: string
  user?: string
  rule_description?: string
  severity?: string
}

interface ThreatGraphProps {
  alert: AlertData
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: '#f87171',
  HIGH: '#fbbf24',
  MEDIUM: '#38bdf8',
  LOW: '#34d399'
}

export default function ThreatGraph({ alert }: ThreatGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<cytoscape.Core | null>(null)

  useEffect(() => {
    if (!containerRef.current) return

    const color = SEVERITY_COLOR[alert.severity?.toUpperCase() ?? 'MEDIUM'] ?? '#38bdf8'

    const nodes: cytoscape.NodeDefinition[] = [
      {
        data: {
          id: 'alert',
          label: '⚠ Alert',
          sublabel: alert.rule_description?.slice(0, 30) ?? alert.id,
          type: 'alert',
          color
        }
      }
    ]
    const edges: cytoscape.EdgeDefinition[] = []

    if (alert.agent_id) {
      nodes.push({
        data: {
          id: 'agent',
          label: '⬡ Agent',
          sublabel: alert.agent_name ?? alert.agent_id,
          type: 'agent',
          color: '#8b5cf6'
        }
      })
      edges.push({ data: { source: 'alert', target: 'agent' } })
    }
    if (alert.source_ip) {
      nodes.push({
        data: {
          id: 'src_ip',
          label: '⊕ Source IP',
          sublabel: alert.source_ip,
          type: 'ip',
          color: '#f87171'
        }
      })
      edges.push({ data: { source: 'alert', target: 'src_ip' } })
    }
    if (alert.destination_ip) {
      nodes.push({
        data: {
          id: 'dst_ip',
          label: '◈ Dest IP',
          sublabel: alert.destination_ip,
          type: 'ip',
          color: '#fbbf24'
        }
      })
      edges.push({ data: { source: 'alert', target: 'dst_ip' } })
    }
    if (alert.user) {
      nodes.push({
        data: { id: 'user', label: '◉ User', sublabel: alert.user, type: 'user', color: '#34d399' }
      })
      edges.push({ data: { source: 'agent', target: 'user' } })
    }

    cyRef.current?.destroy()
    cyRef.current = cytoscape({
      container: containerRef.current,
      elements: [...nodes, ...edges],
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            'background-opacity': 0.15,
            'border-color': 'data(color)',
            'border-width': 1.5,
            width: 90,
            height: 90,
            label: 'data(label)',
            'text-valign': 'center',
            'text-halign': 'center',
            color: '#e2e8f0',
            'font-size': 9,
            'font-family': 'Inter, system-ui, sans-serif',
            'text-wrap': 'wrap',
            'text-max-width': '80px'
          }
        },
        {
          selector: 'node[id="alert"]',
          style: {
            width: 110,
            height: 110,
            'border-width': 2,
            'font-size': 10,
            'font-weight': 600
          }
        },
        {
          selector: 'edge',
          style: {
            width: 1,
            'line-color': 'rgba(100,116,139,0.4)',
            'target-arrow-color': 'rgba(100,116,139,0.4)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.8
          }
        },
        {
          selector: ':selected',
          style: {
            'border-width': 2.5,
            'background-opacity': 0.3
          }
        }
      ],
      layout: {
        name: 'cose',
        padding: 20,
        animate: false,
        nodeRepulsion: () => 6000,
        idealEdgeLength: () => 120
      }
    })

    return () => {
      cyRef.current?.destroy()
      cyRef.current = null
    }
  }, [alert])

  return (
    <div
      ref={containerRef}
      style={{
        width: '100%',
        height: 280,
        background: 'rgba(0,0,0,0.3)',
        borderRadius: 6,
        border: '1px solid rgba(56,189,248,0.12)'
      }}
    />
  )
}
