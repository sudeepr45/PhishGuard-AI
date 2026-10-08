const outputSections = [
  { label: 'RISK ASSESSMENT', detail: 'Risk output will appear here once the analysis engine is connected.' },
  { label: 'EVIDENCE', detail: 'Signal data will appear here.' },
  { label: 'KNOWN PATTERN SIGNALS', detail: 'Awaiting model output.' },
  { label: 'NOVELTY SIGNALS', detail: 'Awaiting model output.' },
  { label: 'EXPLANATION', detail: 'A human-readable explanation will appear here.' },
]

const evidenceTypes = ['URL STRUCTURE', 'DOMAIN CHARACTERISTICS', 'CONTENT SIGNALS', 'CONTEXTUAL SIGNALS', 'KNOWN PATTERN MATCH', 'NOVELTY INDICATORS']

export function AnalysisArchitecture() {
  return (
    <section className="analysis-architecture" aria-labelledby="architecture-title">
      <div className="analysis-section-heading">
        <div><span className="section-index">03 / FUTURE OUTPUT</span><h2 id="architecture-title">Result architecture</h2></div>
        <span className="pipeline-footnote">NO MODEL OUTPUT</span>
      </div>
      <div className="output-grid">
        {outputSections.map(({ label, detail }) => (
          <article key={label} className="output-placeholder">
            <h3>{label}</h3>
            <p>{detail}</p>
            <span>NOT CONNECTED</span>
          </article>
        ))}
      </div>
      <div className="evidence-structure">
        <span className="section-index">POTENTIAL EVIDENCE CATEGORIES</span>
        <ul>{evidenceTypes.map((type) => <li key={type}>{type}<span>AWAITING MODEL OUTPUT</span></li>)}</ul>
      </div>
    </section>
  )
}
