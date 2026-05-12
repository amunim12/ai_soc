import { useCallback, useEffect, useRef, useState } from 'react'
import { api, RagCollection } from '../lib/api'

const COLLECTIONS = [
  'mitre_attack',
  'nvd_cves',
  'wazuh_rules',
  'past_incidents',
  'nist_csf',
  'custom_intel',
]

export default function VectorDB() {
  const [collections, setCollections] = useState<RagCollection[]>([])
  const [loadingCols, setLoadingCols] = useState(true)
  const [selectedCollection, setSelectedCollection] = useState('custom_intel')
  const [dragging, setDragging] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const loadCollections = useCallback(async () => {
    try {
      const data = await api.ragCollections()
      setCollections(data)
    } catch {
      // backend may be offline
    } finally {
      setLoadingCols(false)
    }
  }, [])

  useEffect(() => {
    loadCollections()
    const t = setInterval(loadCollections, 500)
    return () => clearInterval(t)
  }, [loadCollections])

  function onDrop(e: React.DragEvent) {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) setFile(f)
  }

  async function upload() {
    if (!file) return
    setUploading(true)
    setError(null)
    setResult(null)
    try {
      const form = new FormData()
      form.append('file', file)
      form.append('collection', selectedCollection)
      form.append('source', file.name)
      const res = await api.ragUpload(form)
      setResult(`✓ Ingested ${res.ingested_chunks} chunks into "${res.collection}" (SHA256: ${res.sha256.slice(0, 12)}…)`)
      setFile(null)
      await loadCollections()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setUploading(false)
    }
  }

  const fileSizeMB = file ? (file.size / 1024 / 1024).toFixed(1) : null

  return (
    <div className="page-content animate-in">
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 18, fontWeight: 700, color: '#e2e8f0', marginBottom: 4 }}>
          Vector Database
        </div>
        <div style={{ fontSize: 12, color: '#64748b' }}>
          Ingest PDF / DOCX threat intelligence into the local on-premise ChromaDB RAG engine
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 16 }}>
        {/* Upload panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Drop zone */}
          <div
            className="glass"
            onDragOver={e => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            onClick={() => inputRef.current?.click()}
            style={{
              padding: 40,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 12,
              cursor: 'pointer',
              border: `2px dashed ${dragging ? 'rgba(139,92,246,0.6)' : 'rgba(56,189,248,0.2)'}`,
              background: dragging ? 'rgba(139,92,246,0.06)' : undefined,
              transition: 'all 0.15s',
              minHeight: 200,
            }}
          >
            <input
              ref={inputRef}
              type="file"
              accept=".pdf,.docx"
              style={{ display: 'none' }}
              onChange={e => e.target.files?.[0] && setFile(e.target.files[0])}
            />
            {file ? (
              <>
                <div style={{ fontSize: 36 }}>📄</div>
                <div style={{ fontWeight: 600, color: '#e2e8f0' }}>{file.name}</div>
                <div style={{ fontSize: 12, color: '#64748b' }}>{fileSizeMB} MB · {file.type || 'document'}</div>
                <button
                  className="btn btn-ghost"
                  style={{ fontSize: 11 }}
                  onClick={e => { e.stopPropagation(); setFile(null) }}
                >
                  Remove
                </button>
              </>
            ) : (
              <>
                <div style={{ fontSize: 40, opacity: 0.4 }}>⊞</div>
                <div style={{ fontWeight: 600, color: '#94a3b8' }}>Drop PDF or DOCX here</div>
                <div style={{ fontSize: 12, color: '#64748b' }}>or click to browse · max 50 MB</div>
              </>
            )}
          </div>

          {/* Collection selector */}
          <div className="glass" style={{ padding: 16 }}>
            <div className="section-title">Target Collection</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {COLLECTIONS.map(col => (
                <button
                  key={col}
                  onClick={() => setSelectedCollection(col)}
                  style={{
                    padding: '5px 10px',
                    borderRadius: 5,
                    fontSize: 11,
                    fontWeight: 600,
                    cursor: 'pointer',
                    border: `1px solid ${selectedCollection === col ? 'rgba(139,92,246,0.5)' : 'rgba(255,255,255,0.08)'}`,
                    background: selectedCollection === col ? 'rgba(139,92,246,0.15)' : 'transparent',
                    color: selectedCollection === col ? '#c4b5fd' : '#64748b',
                    transition: 'all 0.15s',
                  }}
                >
                  {col}
                </button>
              ))}
            </div>
          </div>

          {error && (
            <div style={{ padding: '10px 14px', background: 'rgba(248,113,113,0.1)', border: '1px solid rgba(248,113,113,0.2)', borderRadius: 6, color: '#f87171', fontSize: 12 }}>
              ⚠ {error}
            </div>
          )}
          {result && (
            <div style={{ padding: '10px 14px', background: 'rgba(52,211,153,0.1)', border: '1px solid rgba(52,211,153,0.2)', borderRadius: 6, color: '#34d399', fontSize: 12 }}>
              {result}
            </div>
          )}

          <button
            className="btn btn-primary"
            onClick={upload}
            disabled={!file || uploading}
            style={{ justifyContent: 'center', padding: '11px 0' }}
          >
            {uploading ? <><span className="spinner" /> Ingesting…</> : '⊕ Ingest Document'}
          </button>
        </div>

        {/* Collections panel */}
        <div className="glass" style={{ padding: 16, alignSelf: 'start' }}>
          <div className="section-title">Collections</div>
          {loadingCols ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 20 }}>
              <div className="spinner" />
            </div>
          ) : collections.length === 0 ? (
            <div className="empty-state" style={{ padding: '20px 0' }}>
              <div style={{ fontSize: 11, color: '#475569' }}>No collections found</div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {collections.map(col => (
                <div
                  key={col.name}
                  style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '8px 10px',
                    background: 'rgba(255,255,255,0.03)',
                    borderRadius: 6,
                    border: '1px solid rgba(255,255,255,0.05)',
                  }}
                >
                  <span style={{ fontSize: 12, color: '#94a3b8' }}>{col.name}</span>
                  <span
                    style={{
                      fontSize: 11, fontWeight: 700,
                      padding: '2px 7px', borderRadius: 99,
                      background: 'rgba(139,92,246,0.12)',
                      color: '#c4b5fd',
                      border: '1px solid rgba(139,92,246,0.2)',
                    }}
                  >
                    {col.count}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
