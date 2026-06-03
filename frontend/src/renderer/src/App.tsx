import { useEffect, useState, useCallback } from 'react'
import Sidebar from './components/Sidebar'
import DashboardOverview from './pages/DashboardOverview'
import HitlQueue from './pages/HitlQueue'
import ReviewDetails from './pages/ReviewDetails'
import ExecutionHistory from './pages/ExecutionHistory'
import VectorDB from './pages/VectorDB'
import SiemView from './pages/SiemView'
import ShuffleView from './pages/ShuffleView'
import LogSources from './pages/LogSources'
import Login from './pages/Login'
import { SetupWizard } from './components/SetupWizard'
import { ServiceStatusBar } from './components/ServiceStatusBar'
import { api, PendingReview } from './lib/api'
import { loadAuth, saveAuth, clearAuth } from './lib/auth'
import type { AuthUser } from './lib/auth'

type Page = 'dashboard' | 'hitl' | 'history' | 'vectordb' | 'siem' | 'shuffle' | 'logsources'

export default function App() {
  const [setupComplete, setSetupComplete] = useState<boolean | null>(null)

  // Check setup on mount (only in Electron context)
  useEffect(() => {
    if (typeof window !== 'undefined' && window.backend) {
      void window.backend.isSetupComplete().then(setSetupComplete)
    } else {
      // Browser dev mode: defer via microtask to avoid synchronous setState-in-effect
      void Promise.resolve(true).then(setSetupComplete)
    }
  }, [])

  // Show nothing while checking setup
  if (setupComplete === null) return null

  // Show setup wizard on first run
  if (!setupComplete) {
    return <SetupWizard onComplete={() => setSetupComplete(true)} />
  }

  return <MainApp />
}

function MainApp() {
  const [user, setUser] = useState<AuthUser | null>(() => loadAuth())
  const [page, setPage] = useState<Page>('dashboard')
  const [selectedReview, setSelectedReview] = useState<PendingReview | null>(null)
  const [pendingCount, setPendingCount] = useState(0)

  const refreshPendingCount = useCallback(async () => {
    if (!user) return
    try {
      const reviews = await api.pendingReviews()
      setPendingCount(reviews.length)
    } catch {
      // silently ignore — backend might be offline
    }
  }, [user])

  useEffect(() => {
    // refreshPendingCount is async — setState inside it is deferred past the await,
    // so it does not trigger a synchronous cascading render from the effect.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void refreshPendingCount()
    const t = setInterval(() => void refreshPendingCount(), 500)
    return () => clearInterval(t)
  }, [refreshPendingCount])

  function handleLogin(data: AuthUser) {
    saveAuth(data)
    setUser(data)
  }

  function handleLogout() {
    clearAuth()
    setUser(null)
    setPage('dashboard')
    setSelectedReview(null)
  }

  function navigate(p: string) {
    setPage(p as Page)
    setSelectedReview(null)
  }

  function openReview(review: PendingReview) {
    setSelectedReview(review)
  }

  function closeReview() {
    setSelectedReview(null)
  }

  function onDecisionMade(_action?: string) {
    setSelectedReview(null)
    refreshPendingCount()
    // Navigate to dashboard so the Overview metrics (Escalated, Pending, etc.)
    // are immediately visible after any HITL decision.
    setPage('dashboard')
  }

  // ── Auth gate ──────────────────────────────────────────────
  if (!user) {
    return <Login onLogin={handleLogin} />
  }

  // ── Pages that replace the chrome entirely (no topbar) ────
  if (page === 'siem') return <SiemView onBack={() => setPage('dashboard')} />
  if (page === 'shuffle') return <ShuffleView onBack={() => setPage('dashboard')} />
  if (page === 'logsources') return <LogSources onBack={() => setPage('dashboard')} />

  const topbarTitles: Record<
    Exclude<Page, 'siem' | 'shuffle' | 'logsources'>,
    { title: string; sub: string }
  > = {
    dashboard: { title: 'Overview', sub: 'Pipeline health & 24-hour telemetry' },
    hitl: { title: 'HITL Review Queue', sub: 'Human-in-the-loop threat decisions' },
    history: { title: 'Execution History', sub: 'SOAR workflow audit log' },
    vectordb: { title: 'Vector Database', sub: 'ChromaDB RAG knowledge base' }
  }

  const { title, sub } = selectedReview
    ? { title: 'Threat Investigation', sub: 'Deep-dive incident review' }
    : topbarTitles[page as Exclude<Page, 'siem' | 'shuffle' | 'logsources'>]

  return (
    <div className="page-layout">
      <Sidebar
        active={page}
        onNavigate={navigate}
        pendingCount={pendingCount}
        user={user}
        onLogout={handleLogout}
      />

      <div className="main-area">
        {/* Topbar */}
        <div className="topbar">
          <div style={{ flex: 1 }}>
            <div className="topbar-title">{title}</div>
            <div className="topbar-sub">{sub}</div>
          </div>

          <Clock />

          <div
            style={{ width: 1, height: 24, background: 'rgba(255,255,255,0.07)', margin: '0 4px' }}
          />

          <ServiceStatusBar />
        </div>

        {/* Page content */}
        {selectedReview ? (
          <ReviewDetails
            key={selectedReview.review_id}
            review={selectedReview}
            onBack={closeReview}
            onDecisionMade={onDecisionMade}
          />
        ) : page === 'dashboard' ? (
          <DashboardOverview key="dashboard" />
        ) : page === 'hitl' ? (
          <HitlQueue key="hitl" onSelectReview={openReview} />
        ) : page === 'vectordb' ? (
          <VectorDB key="vectordb" />
        ) : (
          <ExecutionHistory key="history" />
        )}
      </div>
    </div>
  )
}

function Clock() {
  const [time, setTime] = useState(() => new Date().toLocaleTimeString())
  useEffect(() => {
    const t = setInterval(() => setTime(new Date().toLocaleTimeString()), 1_000)
    return () => clearInterval(t)
  }, [])
  return (
    <div
      style={{
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: 12,
        color: '#475569',
        letterSpacing: '0.05em'
      }}
    >
      {time}
    </div>
  )
}
