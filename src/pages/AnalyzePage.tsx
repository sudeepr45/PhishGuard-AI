import { useState, type FormEvent } from 'react'
import { AnalysisResultView } from '../components/analysis/AnalysisResultView'
import { AnalysisSourceSelector, type AnalysisSource } from '../components/analysis/AnalysisSourceSelector'
import { EmailAnalysisPage } from './EmailAnalysisPage'
import { analyzeUrl, ApiError, validateUrlInput, type UrlAnalysis } from '../services/urlAnalysis'
import './AnalyzePage.css'
import { PUBLIC_DEMO_MODE } from '../runtimeConfig'

type Props = { initialUrl?: string; initialResult?: UrlAnalysis }
type State = 'idle' | 'invalid' | 'loading' | 'success' | 'error'

export function AnalyzePage({ initialUrl = '', initialResult }: Props) {
  const [source, setSource] = useState<AnalysisSource>('url')
  const [url, setUrl] = useState(initialUrl)
  const [state, setState] = useState<State>(initialResult ? 'success' : 'idle')
  const [error, setError] = useState('')
  const [validationError, setValidationError] = useState('')
  const [result, setResult] = useState<UrlAnalysis | null>(initialResult ?? null)

  function changeUrl(value: string) {
    setUrl(value)
    setState('idle')
    setError('')
    setValidationError('')
    setResult(null)
  }

  async function runAnalysis(value: string) {
    const validation = validateUrlInput(value)
    if (validation) {
      setValidationError(validation)
      setState('invalid')
      setResult(null)
      return
    }

    setState('loading')
    setError('')
    setValidationError('')
    setResult(null)
    try {
      const response = await analyzeUrl(value.trim())
      setResult(response)
      setState('success')
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Analysis failed. Try again.'
      if (caught instanceof ApiError && caught.status === 422) {
        setValidationError(message)
        setState('invalid')
      } else {
        setError(message)
        setState('error')
      }
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (state !== 'loading') void runAnalysis(url)
  }

  function reset() {
    changeUrl('')
  }

  if (source === 'email') return <EmailAnalysisPage onSelectSource={setSource} />

  return (
    <div className="analysis-page">
      <header className="analysis-heading">
        <div className="eyebrow"><span className="eyebrow-line" /> PHISHGUARD / URL ANALYSIS</div>
        <p className="kicker">URL-ONLY CLASSIFICATION</p>
        <h1>Analyze URL text.</h1>
        <p className="analysis-lede">The selected model measures URL structure and classifies the submitted string. It does not visit the destination or verify current website behavior.</p>
      </header>

      <div className="analysis-layout">
        <section className="analysis-input-panel" aria-labelledby="analysis-input-title">
          <div className="analysis-panel-heading">
            <div><span className="section-index">INPUT / 01</span><h2 id="analysis-input-title">URL to examine</h2></div>
            <span className="prototype-label">LOCAL MODEL</span>
          </div>
          <AnalysisSourceSelector selected="url" onSelect={setSource} />
          <form className="workspace-form" onSubmit={submit} noValidate>
            <label htmlFor="analysis-source-input" className="workspace-input-label">HTTP OR HTTPS URL</label>
            <input id="analysis-source-input" type="text" inputMode="url" value={url}
              onChange={(event) => changeUrl(event.target.value)}
              placeholder="https://example.com/login" autoComplete="url"
              aria-invalid={state === 'invalid'} aria-describedby={state === 'invalid' ? 'analysis-input-hint analysis-input-error' : 'analysis-input-hint'} />
            <p id="analysis-input-hint" className="workspace-hint">{PUBLIC_DEMO_MODE
              ? 'A scheme-less host is treated as HTTPS. Public demo analyses are not saved.'
              : 'A scheme-less host is treated as HTTPS. The URL is stored locally after a successful analysis.'}</p>
            {state === 'invalid' && <p id="analysis-input-error" className="validation-message" role="alert">{validationError}</p>}
            <button type="submit" className="button button-primary workspace-submit" disabled={state === 'loading'}>
              {state === 'loading' ? 'ANALYZING…' : 'ANALYZE URL'} <span aria-hidden="true">→</span>
            </button>
          </form>
        </section>

        <section className={`analysis-status state-${state}`} aria-labelledby="status-title" aria-live="polite">
          <div className="analysis-panel-heading">
            <div><span className="section-index">RESULT / 02</span><h2 id="status-title">
              {state === 'loading' ? 'Analysis in progress' : state === 'success' ? 'Model prediction' : state === 'error' ? 'Analysis unavailable' : state === 'invalid' ? 'Check the URL' : 'Ready to analyze'}
            </h2></div>
            <span className="state-indicator" aria-hidden="true" />
          </div>
          {state === 'loading' && <div className="loading-state"><span className="loading-mark" aria-hidden="true" /><span>{PUBLIC_DEMO_MODE
            ? 'Running URL analysis with the selected model.'
            : 'Waiting for the local model and saving its result to local history.'}</span></div>}
          {state === 'idle' && <p className="status-copy">Submit a URL to receive the actual model prediction, scores, and 17 measured URL features.</p>}
          {state === 'invalid' && <p className="status-copy" role="alert">{validationError}</p>}
          {state === 'error' && <div className="analysis-error" role="alert"><p>{error}</p><button type="button" className="new-analysis-button" onClick={() => void runAnalysis(url)}>TRY AGAIN</button></div>}
          {result && state === 'success' && <>
            <AnalysisResultView result={result} />
            <button type="button" className="new-analysis-button" onClick={reset}>ANALYZE ANOTHER URL</button>
          </>}
        </section>
      </div>

      <section className="analysis-limitations" aria-labelledby="limits-title">
        <span className="section-index">SCOPE / 03</span><h2 id="limits-title">What this result can tell you</h2>
        <p>The classifier uses 17 URL-string features from the PhiUSIIL dataset. It does not analyze page content, check domain reputation, detect every phishing attempt, or establish that a destination is safe. Treat the output as a research model prediction.</p>
      </section>
    </div>
  )
}
