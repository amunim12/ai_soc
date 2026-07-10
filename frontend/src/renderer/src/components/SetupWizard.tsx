import { useState, useEffect } from 'react'

type Step = 'docker' | 'secrets' | 'llm' | 'review' | 'installing'

interface Config {
  JWT_SECRET_KEY: string
  POSTGRES_PASSWORD: string
  REDIS_PASSWORD: string
  LOCAL_LLM_BASE_URL: string
  LOCAL_LLM_MODEL: string
  DEFAULT_ADMIN_PASSWORD: string
}

interface Props {
  onComplete: () => void
}

export function SetupWizard({ onComplete }: Props) {
  const [step, setStep] = useState<Step>('docker')
  const [dockerOk, setDockerOk] = useState<boolean | null>(null)
  const [installMsg, setInstallMsg] = useState('')
  const [config, setConfig] = useState<Config>({
    JWT_SECRET_KEY: '',
    POSTGRES_PASSWORD: '',
    REDIS_PASSWORD: '',
    LOCAL_LLM_BASE_URL: 'http://localhost:8001/v1',
    LOCAL_LLM_MODEL: 'Qwen/Qwen2.5-72B-Instruct-AWQ',
    DEFAULT_ADMIN_PASSWORD: ''
  })

  useEffect(() => {
    if (step === 'docker') {
      setDockerOk(null)
      window.backend.checkDocker().then(setDockerOk)
    }
  }, [step])

  async function generateSecrets() {
    const [jwt, pg, redis, admin] = await Promise.all([
      window.backend.generateSecret(),
      window.backend.generateSecret(),
      window.backend.generateSecret(),
      window.backend.generateSecret()
    ])
    setConfig((c) => ({
      ...c,
      JWT_SECRET_KEY: jwt,
      POSTGRES_PASSWORD: pg.slice(0, 32),
      REDIS_PASSWORD: redis.slice(0, 32),
      DEFAULT_ADMIN_PASSWORD: admin.slice(0, 20)
    }))
  }

  async function install() {
    setStep('installing')
    setInstallMsg('Writing configuration...')

    const full: Record<string, string> = {
      ...config,
      DEFAULT_ADMIN_USER: 'admin',
      JWT_ALGORITHM: 'HS256',
      JWT_EXPIRE_MINUTES: '480',
      KAFKA_BOOTSTRAP_SERVERS: 'localhost:9092',
      KAFKA_GROUP_ID: 'ai_soc',
      REDIS_URL: `redis://:${config.REDIS_PASSWORD}@localhost:6379/0`,
      CHROMA_HOST: 'localhost',
      CHROMA_PORT: '8888',
      POSTGRES_DSN: `postgresql://soc:${config.POSTGRES_PASSWORD}@localhost:5432/soc_pipeline`,
      SQLITE_DB_PATH: './data/hitl.db',
      USE_MOCK_TI: 'true',
      LOCAL_AI_ONLY: 'true',
      SOAR_ENABLED: 'false',
      LOG_LEVEL: 'INFO',
      PIPELINE_MAX_CONCURRENT_ALERTS: '512',
      KAFKA_NUM_CONSUMER_WORKERS: '16',
      LLM_MAX_CONCURRENT_CALLS: '64',
      LLM_CALL_TIMEOUT_SECONDS: '30.0',
      PLAYBOOK_CACHE_TTL_SECONDS: '3600',
      RAG_CTX_CACHE_TTL_SECONDS: '3600',
      WAZUH_POLL_INTERVAL: '1',
      WAZUH_BATCH_SIZE: '1200'
    }

    await window.backend.writeEnv(full)
    setInstallMsg('Starting AI SOC services...')
    await window.backend.startServices()

    let attempts = 0
    const poll = setInterval(async () => {
      const status = await window.backend.getStatus()
      attempts++
      if (status === 'running') {
        clearInterval(poll)
        setInstallMsg('All services are running!')
        setTimeout(onComplete, 1200)
      } else if (status === 'error' || attempts > 60) {
        clearInterval(poll)
        setInstallMsg(
          'Some services failed to start. Check that Docker Desktop is running and try again.'
        )
      }
    }, 2000)
  }

  const steps: Step[] = ['docker', 'secrets', 'llm', 'review']
  const stepIndex = steps.indexOf(step === 'installing' ? 'review' : step)

  return (
    <div className="wizard-overlay">
      <div className="wizard-card">
        {/* Header */}
        <div className="wizard-header">
          <div className="wizard-logo">AI</div>
          <div>
            <div className="wizard-title">AI SOC Setup</div>
            <div className="wizard-subtitle">First-time configuration</div>
          </div>
        </div>

        {/* Step dots */}
        <div className="wizard-steps">
          {steps.map((s, i) => (
            <div key={s} className={`wizard-step-dot ${i <= stepIndex ? 'active' : ''}`} />
          ))}
        </div>

        {/* Step: Docker */}
        {step === 'docker' && (
          <div className="wizard-body">
            <h2>Step 1 — Docker Desktop</h2>
            <p className="wizard-desc">
              AI SOC uses Docker to run its backend services. Docker Desktop must be running before
              installation.
            </p>
            {dockerOk === null && <p className="wizard-checking">Checking Docker…</p>}
            {dockerOk === true && (
              <>
                <p className="wizard-ok">Docker Desktop is running.</p>
                <div className="wizard-actions">
                  <button className="btn-primary" onClick={() => setStep('secrets')}>
                    Next →
                  </button>
                </div>
              </>
            )}
            {dockerOk === false && (
              <>
                <p className="wizard-error">Docker Desktop is not running or not installed.</p>
                <p className="wizard-desc">
                  Install Docker Desktop from <strong>docker.com/products/docker-desktop</strong>,
                  start it, then click Retry.
                </p>
                <div className="wizard-actions">
                  <button
                    className="btn-secondary"
                    onClick={() => window.backend.checkDocker().then(setDockerOk)}
                  >
                    Retry
                  </button>
                </div>
              </>
            )}
          </div>
        )}

        {/* Step: Secrets */}
        {step === 'secrets' && (
          <div className="wizard-body">
            <h2>Step 2 — Generate Credentials</h2>
            <p className="wizard-desc">
              Click below to generate cryptographically secure credentials for all services. These
              are stored locally and never leave your machine.
            </p>
            <button className="btn-generate" onClick={generateSecrets}>
              Generate Credentials
            </button>
            {config.JWT_SECRET_KEY && (
              <div className="wizard-creds">
                <div className="cred-row">
                  <span className="cred-label">Admin Password</span>
                  <span className="cred-value">{config.DEFAULT_ADMIN_PASSWORD}</span>
                </div>
                <div className="cred-row">
                  <span className="cred-label">Postgres Password</span>
                  <span className="cred-value">{config.POSTGRES_PASSWORD}</span>
                </div>
                <div className="cred-row">
                  <span className="cred-label">Redis Password</span>
                  <span className="cred-value">{config.REDIS_PASSWORD}</span>
                </div>
                <div className="cred-row">
                  <span className="cred-label">JWT Secret</span>
                  <span className="cred-value cred-trunc">
                    {config.JWT_SECRET_KEY.slice(0, 24)}…
                  </span>
                </div>
              </div>
            )}
            <div className="wizard-actions">
              <button className="btn-secondary" onClick={() => setStep('docker')}>
                ← Back
              </button>
              <button
                className="btn-primary"
                disabled={!config.JWT_SECRET_KEY}
                onClick={() => setStep('llm')}
              >
                Next →
              </button>
            </div>
          </div>
        )}

        {/* Step: LLM */}
        {step === 'llm' && (
          <div className="wizard-body">
            <h2>Step 3 — Local LLM Endpoint</h2>
            <p className="wizard-desc">
              AI SOC runs entirely on-premises. Point to your local vLLM server. Start vLLM with:
              <br />
              <code className="wizard-code">
                docker run --gpus all -p 8001:8000 vllm/vllm-openai --model {config.LOCAL_LLM_MODEL}
              </code>
            </p>
            <div className="wizard-fields">
              <label>
                <span>vLLM Base URL</span>
                <input
                  type="text"
                  value={config.LOCAL_LLM_BASE_URL}
                  onChange={(e) => setConfig((c) => ({ ...c, LOCAL_LLM_BASE_URL: e.target.value }))}
                />
              </label>
              <label>
                <span>Model Name</span>
                <input
                  type="text"
                  value={config.LOCAL_LLM_MODEL}
                  onChange={(e) => setConfig((c) => ({ ...c, LOCAL_LLM_MODEL: e.target.value }))}
                />
              </label>
            </div>
            <div className="wizard-actions">
              <button className="btn-secondary" onClick={() => setStep('secrets')}>
                ← Back
              </button>
              <button className="btn-primary" onClick={() => setStep('review')}>
                Next →
              </button>
            </div>
          </div>
        )}

        {/* Step: Review */}
        {step === 'review' && (
          <div className="wizard-body">
            <h2>Step 4 — Review & Install</h2>
            <div className="wizard-summary">
              <div className="summary-row">
                <span>LLM Endpoint</span>
                <span>{config.LOCAL_LLM_BASE_URL}</span>
              </div>
              <div className="summary-row">
                <span>Model</span>
                <span>{config.LOCAL_LLM_MODEL}</span>
              </div>
              <div className="summary-row">
                <span>Admin Username</span>
                <span>admin</span>
              </div>
              <div className="summary-row">
                <span>Admin Password</span>
                <span>{config.DEFAULT_ADMIN_PASSWORD || '(not generated)'}</span>
              </div>
            </div>
            <p className="wizard-desc">
              Clicking Install will write your <code>.env</code> to{' '}
              <code>{typeof window !== 'undefined' ? 'AppData/ai-soc/' : '~/.config/ai-soc/'}</code>{' '}
              and start all Docker services.
            </p>
            <div className="wizard-actions">
              <button className="btn-secondary" onClick={() => setStep('llm')}>
                ← Back
              </button>
              <button className="btn-install" disabled={!config.JWT_SECRET_KEY} onClick={install}>
                Install & Launch
              </button>
            </div>
          </div>
        )}

        {/* Step: Installing */}
        {step === 'installing' && (
          <div className="wizard-body wizard-installing">
            <div className="install-spinner" />
            <p className="install-title">Setting Up AI SOC</p>
            <p className="install-msg">{installMsg}</p>
          </div>
        )}
      </div>

      <style>{`
        .wizard-overlay {
          position: fixed; inset: 0;
          background: #060a14;
          display: flex; align-items: center; justify-content: center;
          padding: 2rem;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          color: #e2e8f0;
        }
        .wizard-card {
          width: 100%; max-width: 560px;
          background: #0d1424;
          border: 1px solid #1e2d4a;
          border-radius: 16px;
          padding: 2rem;
          box-shadow: 0 24px 64px rgba(0,0,0,0.5);
        }
        .wizard-header { display: flex; align-items: center; gap: 12px; margin-bottom: 1.5rem; }
        .wizard-logo {
          width: 40px; height: 40px; border-radius: 10px;
          background: #2563eb; display: flex; align-items: center; justify-content: center;
          font-weight: 800; font-size: 14px; letter-spacing: -0.02em;
        }
        .wizard-title { font-weight: 600; font-size: 1rem; }
        .wizard-subtitle { font-size: 0.78rem; color: #64748b; }
        .wizard-steps { display: flex; gap: 6px; margin-bottom: 1.5rem; }
        .wizard-step-dot {
          width: 24px; height: 4px; border-radius: 2px;
          background: #1e2d4a; transition: background 0.2s;
        }
        .wizard-step-dot.active { background: #3b82f6; }
        .wizard-body h2 { font-size: 1.05rem; font-weight: 600; margin-bottom: 0.75rem; }
        .wizard-desc { font-size: 0.875rem; color: #94a3b8; line-height: 1.6; margin-bottom: 1rem; }
        .wizard-checking { font-size: 0.875rem; color: #64748b; font-style: italic; }
        .wizard-ok { color: #34d399; font-size: 0.875rem; margin-bottom: 1rem; }
        .wizard-error { color: #f87171; font-size: 0.875rem; margin-bottom: 0.5rem; }
        .wizard-code {
          display: block; margin-top: 0.5rem; padding: 0.5rem 0.75rem;
          background: #060a14; border: 1px solid #1e2d4a; border-radius: 6px;
          font-size: 0.75rem; color: #7dd3fc; word-break: break-all;
        }
        .wizard-fields { display: flex; flex-direction: column; gap: 0.75rem; margin-bottom: 1.25rem; }
        .wizard-fields label { display: flex; flex-direction: column; gap: 4px; font-size: 0.8rem; color: #94a3b8; }
        .wizard-fields input {
          background: #060a14; border: 1px solid #1e2d4a; border-radius: 8px;
          padding: 0.5rem 0.75rem; color: #e2e8f0; font-size: 0.875rem;
        }
        .wizard-fields input:focus { outline: none; border-color: #3b82f6; }
        .btn-generate {
          display: inline-flex; align-items: center; gap: 6px;
          padding: 0.5rem 1rem; background: #4f46e5; border: none; border-radius: 8px;
          color: #fff; font-size: 0.875rem; font-weight: 500; cursor: pointer;
          margin-bottom: 1rem;
        }
        .btn-generate:hover { background: #4338ca; }
        .wizard-creds {
          background: #060a14; border: 1px solid #1e2d4a; border-radius: 10px;
          padding: 0.75rem 1rem; margin-bottom: 1.25rem;
        }
        .cred-row {
          display: flex; justify-content: space-between; align-items: center;
          padding: 0.35rem 0; border-bottom: 1px solid #1e2d4a; font-size: 0.8rem;
        }
        .cred-row:last-child { border-bottom: none; }
        .cred-label { color: #64748b; }
        .cred-value { color: #34d399; font-family: 'JetBrains Mono', monospace; }
        .cred-trunc { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .wizard-summary {
          background: #060a14; border: 1px solid #1e2d4a; border-radius: 10px;
          padding: 0.75rem 1rem; margin-bottom: 1.25rem;
        }
        .summary-row {
          display: flex; justify-content: space-between;
          padding: 0.35rem 0; border-bottom: 1px solid #1e2d4a; font-size: 0.8rem;
        }
        .summary-row:last-child { border-bottom: none; }
        .summary-row span:first-child { color: #64748b; }
        .wizard-actions { display: flex; gap: 0.75rem; margin-top: 1.25rem; }
        .btn-primary {
          padding: 0.55rem 1.25rem; background: #2563eb; border: none; border-radius: 8px;
          color: #fff; font-size: 0.875rem; font-weight: 600; cursor: pointer;
        }
        .btn-primary:hover { background: #1d4ed8; }
        .btn-primary:disabled { opacity: 0.4; cursor: not-allowed; }
        .btn-secondary {
          padding: 0.55rem 1.25rem; background: #1e2d4a; border: none; border-radius: 8px;
          color: #94a3b8; font-size: 0.875rem; font-weight: 500; cursor: pointer;
        }
        .btn-secondary:hover { background: #253552; color: #e2e8f0; }
        .btn-install {
          padding: 0.55rem 1.5rem; background: #16a34a; border: none; border-radius: 8px;
          color: #fff; font-size: 0.875rem; font-weight: 600; cursor: pointer;
        }
        .btn-install:hover { background: #15803d; }
        .btn-install:disabled { opacity: 0.4; cursor: not-allowed; }
        .wizard-installing { text-align: center; padding: 2rem 0; }
        .install-spinner {
          width: 40px; height: 40px; margin: 0 auto 1.25rem;
          border: 3px solid #1e2d4a; border-top-color: #3b82f6;
          border-radius: 50%; animation: spin 0.8s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .install-title { font-size: 1rem; font-weight: 600; margin-bottom: 0.5rem; }
        .install-msg { font-size: 0.875rem; color: #64748b; }
      `}</style>
    </div>
  )
}
