import { useState, type FormEvent } from 'react'

export type InputMode = 'url' | 'website' | 'email'

const modes: { id: InputMode; label: string }[] = [
  { id: 'url', label: 'URL' },
  { id: 'website', label: 'Website' },
  { id: 'email', label: 'Email' },
]

const fieldCopy: Record<InputMode, { label: string; placeholder: string; hint: string }> = {
  url: { label: 'URL to examine', placeholder: 'https://example.com', hint: 'Enter a URL as a future analysis input.' },
  website: { label: 'Website address', placeholder: 'https://example.com', hint: 'Website inspection is planned; no page is opened here.' },
  email: { label: 'Email content', placeholder: 'Paste email text to prepare a future analysis…', hint: 'Email content stays in this browser and is not submitted.' },
}

type AnalysisInputProps = {
  onSubmit: (mode: InputMode) => void
}

export function AnalysisInput({ onSubmit }: AnalysisInputProps) {
  const [mode, setMode] = useState<InputMode>('url')
  const [inputs, setInputs] = useState<Record<InputMode, string>>({ url: '', website: '', email: '' })
  const copy = fieldCopy[mode]

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    onSubmit(mode)
  }

  return (
    <section className="analysis-entry" aria-labelledby="entry-title">
      <div className="entry-heading">
        <div>
          <span className="section-index">INPUT / 01</span>
          <h2 id="entry-title">Choose a source</h2>
        </div>
        <span className="entry-status"><i aria-hidden="true" /> PROTOTYPE</span>
      </div>
      <div className="mode-tabs" role="group" aria-label="Choose an analysis input type">
        {modes.map(({ id, label }) => (
          <button key={id} type="button" aria-pressed={mode === id} className={mode === id ? 'mode-tab selected' : 'mode-tab'}
            onClick={() => setMode(id)}>{label}</button>
        ))}
      </div>
      <form onSubmit={submit}>
        <label className="input-label" htmlFor="analysis-input">{copy.label}</label>
        {mode === 'email' ? (
          <textarea id="analysis-input" value={inputs[mode]} onChange={(event) => setInputs({ ...inputs, [mode]: event.target.value })}
            placeholder={copy.placeholder} rows={3} />
        ) : (
          <input id="analysis-input" type="url" inputMode="url" value={inputs[mode]} onChange={(event) => setInputs({ ...inputs, [mode]: event.target.value })}
            placeholder={copy.placeholder} autoComplete="url" />
        )}
        <p className="input-hint">{copy.hint}</p>
        <button className="button button-primary entry-submit" type="submit">ANALYZE INPUT <span aria-hidden="true">↗</span></button>
      </form>
      <p className="entry-disclaimer">No scan runs in this prototype. Continue to the planned analysis workspace.</p>
    </section>
  )
}
