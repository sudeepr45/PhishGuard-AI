import { useState, type FormEvent } from 'react'
import { validateUrlInput } from '../../services/urlAnalysis'

export type InputMode = 'url'

type AnalysisInputProps = {
  onSubmit: (mode: InputMode, value: string) => Promise<void>
}

export function AnalysisInput({ onSubmit }: AnalysisInputProps) {
  const [url, setUrl] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitting) return
    const validation = validateUrlInput(url)
    if (validation) {
      setError(validation)
      return
    }
    setError('')
    setSubmitting(true)
    try {
      await onSubmit('url', url.trim())
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'The analysis could not be completed. Try again.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <section className="analysis-entry" aria-labelledby="entry-title">
      <div className="entry-heading">
        <div><span className="section-index">START AN ANALYSIS</span><h2 id="entry-title">Enter a URL to examine</h2></div>
        <span className="entry-status"><i aria-hidden="true" /> LOCAL MODEL</span>
      </div>
      <form onSubmit={submit} noValidate>
        <label className="input-label" htmlFor="analysis-input">HTTP OR HTTPS URL</label>
        <input id="analysis-input" type="text" inputMode="url" value={url}
          onChange={(event) => { setUrl(event.target.value); setError('') }}
          placeholder="https://example.com/login" autoComplete="url"
          aria-invalid={Boolean(error)} aria-describedby={error ? 'entry-input-hint entry-input-error' : 'entry-input-hint'} />
        <p id="entry-input-hint" className="input-hint">Only URL text is analyzed. The destination is never opened.</p>
        {error && <p id="entry-input-error" className="input-error" role="alert">{error}</p>}
        <button className="button button-primary entry-submit" type="submit" disabled={submitting}>
          {submitting ? 'ANALYZING…' : 'ANALYZE URL'} <span aria-hidden="true">→</span>
        </button>
      </form>
      <p className="entry-disclaimer">The prediction is a model output, not a guarantee that a destination is safe.</p>
    </section>
  )
}
