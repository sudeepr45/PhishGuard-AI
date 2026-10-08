import { useEffect, useState, type FormEvent } from 'react'
import { AnalysisArchitecture } from '../components/analysis/AnalysisArchitecture'
import { AnalysisPipeline } from '../components/analysis/AnalysisPipeline'
import { AnalysisSourceSelector, type AnalysisSource } from '../components/analysis/AnalysisSourceSelector'
import './AnalyzePage.css'

type WorkspaceState = 'idle' | 'invalid-input' | 'analyzing' | 'ready-for-model'
type SourceValues = Record<AnalysisSource, string>

const emptyValues: SourceValues = { url: '', website: '', email: '' }

function getSourceFromUrl(): AnalysisSource {
  const type = new URLSearchParams(window.location.search).get('type')?.toLowerCase()
  return type === 'website' || type === 'email' || type === 'url' ? type : 'url'
}

function updateSourceInUrl(source: AnalysisSource) {
  const url = new URL(window.location.href)
  url.searchParams.set('type', source)
  window.history.replaceState(window.history.state, '', `${url.pathname}${url.search}${url.hash}`)
}

function getValidationMessage(source: AnalysisSource, value: string): string | null {
  const trimmed = value.trim()
  if (source === 'email') {
    if (!trimmed) return 'Paste the email content you want to examine.'
    if (trimmed.length < 20) return 'Add more email content before continuing.'
    return null
  }

  if (!trimmed) return 'Enter a URL to continue.'
  if (!/^https?:\/\//i.test(trimmed)) return 'Enter a valid URL beginning with http:// or https://.'

  try {
    const parsed = new URL(trimmed)
    if (!parsed.hostname || (!parsed.hostname.includes('.') && parsed.hostname !== 'localhost')) {
      return 'Enter a valid URL beginning with http:// or https://.'
    }
  } catch {
    return 'Enter a valid URL beginning with http:// or https://.'
  }

  return null
}

export function AnalyzePage() {
  const [source, setSource] = useState<AnalysisSource>(getSourceFromUrl)
  const [values, setValues] = useState<SourceValues>(emptyValues)
  const [hasInteracted, setHasInteracted] = useState(false)
  const [workspaceState, setWorkspaceState] = useState<WorkspaceState>('idle')
  const value = values[source]
  const validationMessage = getValidationMessage(source, value)
  const showValidation = hasInteracted && validationMessage !== null

  useEffect(() => {
    function syncSourceFromUrl() {
      const nextSource = getSourceFromUrl()
      setSource(nextSource)
      updateSourceInUrl(nextSource)
    }

    updateSourceInUrl(getSourceFromUrl())
    window.addEventListener('popstate', syncSourceFromUrl)
    return () => window.removeEventListener('popstate', syncSourceFromUrl)
  }, [])

  useEffect(() => {
    if (workspaceState !== 'analyzing') return
    const timer = window.setTimeout(() => setWorkspaceState('ready-for-model'), 450)
    return () => window.clearTimeout(timer)
  }, [workspaceState])

  function selectSource(nextSource: AnalysisSource) {
    setSource(nextSource)
    setHasInteracted(false)
    setWorkspaceState('idle')
    updateSourceInUrl(nextSource)
  }

  function updateValue(nextValue: string) {
    setValues((current) => ({ ...current, [source]: nextValue }))
    setHasInteracted(true)
    setWorkspaceState(getValidationMessage(source, nextValue) ? 'invalid-input' : 'idle')
  }

  function markInputTouched() {
    setHasInteracted(true)
    setWorkspaceState(validationMessage ? 'invalid-input' : 'idle')
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setHasInteracted(true)
    if (validationMessage) {
      setWorkspaceState('invalid-input')
      return
    }
    setWorkspaceState('analyzing')
  }

  function resetWorkspace() {
    setValues(emptyValues)
    setHasInteracted(false)
    setWorkspaceState('idle')
  }

  const inputId = 'analysis-source-input'
  const hintId = 'analysis-input-hint'
  const errorId = 'analysis-input-error'

  return (
    <div className="analysis-page">
      <header className="analysis-heading">
        <div className="eyebrow"><span className="eyebrow-line" /> PHISHGUARD / ANALYSIS</div>
        <p className="kicker">ANALYSIS WORKSPACE</p>
        <h1>Examine a signal.</h1>
        <p className="analysis-lede">Examine a URL, website, or email for signals associated with phishing.</p>
      </header>

      <div className="analysis-layout">
        <section className="analysis-input-panel" aria-labelledby="source-panel-title">
          <div className="analysis-panel-heading">
            <div><span className="section-index">INPUT / 01</span><h2 id="source-panel-title">Set an analysis source</h2></div>
            <span className="prototype-label">FRONTEND PREVIEW</span>
          </div>

          <AnalysisSourceSelector selected={source} onSelect={selectSource} />

          <form className="workspace-form" onSubmit={submit} noValidate>
            <label htmlFor={inputId} className="workspace-input-label">
              {source === 'url' ? 'URL TO EXAMINE' : source === 'website' ? 'WEBSITE TO EXAMINE' : 'EMAIL CONTENT'}
            </label>
            {source === 'email' ? (
              <textarea id={inputId} value={value} onChange={(event) => updateValue(event.target.value)}
                onBlur={markInputTouched} placeholder="Paste the email content you want to examine..."
                rows={7} aria-invalid={showValidation} aria-describedby={`${hintId}${showValidation ? ` ${errorId}` : ''}`} />
            ) : (
              <input id={inputId} type="text" inputMode="url" value={value} onChange={(event) => updateValue(event.target.value)}
                onBlur={markInputTouched} placeholder="https://example.com"
                aria-invalid={showValidation} aria-describedby={`${hintId}${showValidation ? ` ${errorId}` : ''}`} />
            )}
            <p id={hintId} className="workspace-hint">
              {source === 'url'
                ? 'Enter the complete URL you want to analyze.'
                : source === 'website'
                  ? 'Provide the website address that will be examined by the analysis system.'
                  : 'Include the message content and relevant context where available.'}
            </p>
            {showValidation && <p id={errorId} className="validation-message" role="alert">{validationMessage}</p>}
            <button type="submit" className="button button-primary workspace-submit" disabled={validationMessage !== null}>
              ANALYZE INPUT <span aria-hidden="true">↗</span>
            </button>
          </form>
          <p className="privacy-note">Frontend prototype only. Input stays in this page and is not sent to an analysis service.</p>
        </section>

        <section className={`analysis-status state-${workspaceState}`} aria-labelledby="status-title" aria-live="polite">
          <div className="analysis-panel-heading">
            <div><span className="section-index">WORKSPACE / STATE</span><h2 id="status-title">{workspaceState === 'ready-for-model' ? 'Preview prepared' : workspaceState === 'analyzing' ? 'Preparing preview' : workspaceState === 'invalid-input' ? 'Input needs attention' : 'Ready for input'}</h2></div>
            <span className="state-indicator" aria-hidden="true" />
          </div>
          <p className="status-copy">
            {workspaceState === 'ready-for-model'
              ? 'Frontend workflow preview complete. No analysis was performed; model integration is pending.'
              : workspaceState === 'analyzing'
                ? 'Preparing the frontend workflow preview. No analysis engine is running.'
                : workspaceState === 'invalid-input'
                  ? 'Review the input guidance to continue. No analysis has been performed.'
                  : 'No analysis has been performed. Submit valid input to preview the planned workflow.'}
          </p>
          {workspaceState === 'ready-for-model' && (
            <button type="button" className="new-analysis-button" onClick={resetWorkspace}>NEW ANALYSIS <span aria-hidden="true">↺</span></button>
          )}
          <div className="status-meta"><span className="status-dot" /> MODEL INTEGRATION PENDING</div>
        </section>
      </div>

      <AnalysisPipeline />

      <section className="analysis-dimensions" aria-labelledby="dimensions-title">
        <div className="section-heading">
          <span className="section-index">02 / COMPLEMENTARY ANALYSIS DIMENSIONS</span>
          <h2 id="dimensions-title">Known patterns and novelty are different questions.</h2>
          <p>Novelty is an investigation signal, not a verdict. An unfamiliar pattern does not automatically mean an input is malicious.</p>
        </div>
        <div className="dimension-grid">
          <article><span className="dimension-number">01</span><span className="dimension-label">KNOWN PATTERN ANALYSIS</span><h3>Does the input resemble patterns represented in learned data?</h3><p>Planned classification layer · model output will appear here once connected.</p></article>
          <article><span className="dimension-number">02</span><span className="dimension-label">NOVELTY ANALYSIS</span><h3>Does the input exhibit characteristics that differ from represented patterns?</h3><p>Planned investigation layer · unfamiliarity alone is not a phishing verdict.</p></article>
        </div>
      </section>

      <AnalysisArchitecture />
    </div>
  )
}
