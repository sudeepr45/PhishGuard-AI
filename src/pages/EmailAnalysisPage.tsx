import { useState, type FormEvent } from 'react'
import { AnalysisSourceSelector, type AnalysisSource } from '../components/analysis/AnalysisSourceSelector'
import { AnalysisResultView } from '../components/analysis/AnalysisResultView'
import { analyzeEmail, ApiError, type EmailAnalysis, type EmailLinkAnalysis } from '../services/urlAnalysis'

type Props = { onSelectSource: (source: AnalysisSource) => void }
const MAX_EMAIL_BYTES = 256 * 1024

export function EmailAnalysisPage({ onSelectSource }: Props) {
  const [email, setEmail] = useState('')
  const [result, setResult] = useState<EmailAnalysis | null>(null)
  const [state, setState] = useState<'idle' | 'loading' | 'success' | 'error' | 'invalid'>('idle')
  const [error, setError] = useState('')

  async function runAnalysis() {
    if (!email.trim()) { setError('Paste email content to analyze.'); setState('invalid'); return }
    if (new TextEncoder().encode(email).length > MAX_EMAIL_BYTES) {
      setError('Email content exceeds the 256 KiB limit.'); setState('invalid'); return
    }
    setState('loading'); setError(''); setResult(null)
    try { setResult(await analyzeEmail(email)); setState('success') }
    catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'Email analysis failed. Try again.')
      setState('error')
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); void runAnalysis() }

  function freshStart() { setEmail(''); setResult(null); setError(''); setState('idle') }

  return <div className="analysis-page email-analysis-page">
    <header className="analysis-heading">
      <div className="eyebrow"><span className="eyebrow-line" /> PHISHGUARD / EMAIL TRIAGE</div>
      <p className="kicker">OFFLINE URL SCREENING</p>
      <h1>Inspect email links.</h1>
      <p className="analysis-lede">Paste an email to inspect parsed headers and screen supported links with the active URL model. The message itself is not classified or saved.</p>
    </header>
    <div className="analysis-layout">
      <section className="analysis-input-panel" aria-labelledby="email-input-title">
        <div className="analysis-panel-heading"><div><span className="section-index">INPUT / 01</span><h2 id="email-input-title">Email content</h2></div><span className="prototype-label">LOCAL TRIAGE</span></div>
        <AnalysisSourceSelector selected="email" onSelect={onSelectSource} />
        <form className="workspace-form email-form" onSubmit={submit}>
          <label htmlFor="email-source-input" className="workspace-input-label">RAW EMAIL OR MESSAGE CONTENT</label>
          <textarea id="email-source-input" value={email} onChange={(event) => { setEmail(event.target.value); setState('idle'); setError(''); setResult(null) }}
            placeholder={'From: sender@example.com\nSubject: Please review\n\nPaste the message here…'} maxLength={MAX_EMAIL_BYTES}
            aria-invalid={state === 'invalid'} aria-describedby="email-input-hint" />
          <p id="email-input-hint" className="workspace-hint">Maximum 256 KiB. Parsing runs locally. Links are never opened; pasted content and extracted URLs are not saved.</p>
          {state === 'invalid' && <p className="validation-message" role="alert">{error}</p>}
          <button type="submit" className="button button-primary workspace-submit" disabled={state === 'loading'}>{state === 'loading' ? 'INSPECTING…' : 'ANALYZE EMAIL'} <span aria-hidden="true">→</span></button>
        </form>
      </section>
      <section className={`analysis-status state-${state}`} aria-live="polite" aria-labelledby="email-result-title">
        <div className="analysis-panel-heading"><div><span className="section-index">RESULT / 02</span><h2 id="email-result-title">{state === 'loading' ? 'Inspecting message' : state === 'success' ? 'Link triage' : state === 'error' ? 'Analysis unavailable' : state === 'invalid' ? 'Check the input' : 'Ready to inspect'}</h2></div><span className="state-indicator" aria-hidden="true" /></div>
        {state === 'idle' && <p className="status-copy">Parsed headers and supported links will appear here. Authentication header values are not verified.</p>}
        {state === 'loading' && <div className="loading-state"><span className="loading-mark" aria-hidden="true" /><span>Parsing the message and screening extracted URLs with the local model.</span></div>}
        {state === 'error' && <div className="analysis-error" role="alert"><p>{error}</p><button type="button" className="new-analysis-button" onClick={() => void runAnalysis()}>TRY AGAIN</button></div>}
        {result && state === 'success' && <EmailResult result={result} onReset={freshStart} />}
      </section>
    </div>
    <section className="analysis-limitations"><span className="section-index">SCOPE / 03</span><h2>URL screening is not email classification</h2><p>The service does not verify SPF, DKIM, or DMARC, authenticate sender headers, fetch destinations, or determine whether the email itself is malicious. A legitimate link result does not establish that a message is safe.</p></section>
  </div>
}

function EmailResult({ result, onReset }: { result: EmailAnalysis; onReset: () => void }) {
  return <div className="email-result">
    <p className="email-triage-summary">{result.triage_summary}</p>
    <dl className="email-header-list">{(['From', 'Reply-To', 'Return-Path', 'Subject', 'Date'] as const).map((name) => <div key={name}><dt>{name}</dt><dd>{result.headers[name] || 'Not present'}</dd></div>)}<div><dt>Received headers</dt><dd>{result.received_header_count}</dd></div></dl>
    <section className="email-auth-warning"><h3>Authentication-Results · unverified</h3><p>{result.authentication_results_warning}</p>{result.authentication_results.length ? <ul>{result.authentication_results.map((item, index) => <li key={index}>{item}</li>)}</ul> : <p>No Authentication-Results header was present.</p>}</section>
    <div className="email-counts"><span>{result.extracted_link_count} supported links</span><span>{result.phishing_link_count} phishing predictions</span><span>{result.legitimate_link_count} legitimate predictions</span></div>
    {result.links.map((link, index) => <EmailLink key={`${link.normalized_url}-${index}`} link={link} />)}
    {!!result.unsupported_links.length && <section className="email-unsupported"><h3>Not screened</h3>{result.unsupported_links.map((item, index) => <p key={index}><code>{item.value}</code><span>{item.reason}</span></p>)}</section>}
    {result.truncated && <p className="email-warning">Input processing reached a configured part, content, or link limit. Some content may not be represented.</p>}
    <p className="email-limitations-note">{result.limitations}</p>
    <button type="button" className="new-analysis-button" onClick={onReset}>CLEAR AND ANALYZE ANOTHER EMAIL</button>
  </div>
}

function EmailLink({ link }: { link: EmailLinkAnalysis }) {
  return <details className={`email-link-result email-link-${link.prediction}`}>
    <summary><span className={`prediction prediction-${link.prediction}`}>{link.prediction === 'phishing' ? 'Phishing prediction' : 'Legitimate prediction'}</span><code>{link.normalized_url}</code><small>From {link.sources.join(' and ').replace('_', ' ')}</small></summary>
    <AnalysisResultView result={{ ...link, model_scope: 'URL text only; the destination was not fetched.', interpretation: 'This is a URL model prediction, not a conclusion about the email.' }} />
  </details>
}
