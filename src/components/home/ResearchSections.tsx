import type { InputMode } from './AnalysisInput'

const stages = ['INPUT', 'FEATURES', 'MODEL', 'NOVELTY', 'RISK', 'EXPLANATION']

type ResearchSectionsProps = {
  onAnalyze: (mode: InputMode) => void
}

export function ResearchSections({ onAnalyze }: ResearchSectionsProps) {
  return (
    <>
      <section className="research-questions" aria-labelledby="questions-title">
        <div className="section-heading">
          <span className="section-index">02 / RESEARCH DIRECTION</span>
          <h2 id="questions-title">Two complementary questions.</h2>
          <p>PhishGuard AI explores classification alongside a planned novelty analysis layer.</p>
        </div>
        <div className="question-grid">
          <article className="question-item">
            <span className="question-number">01</span><span className="question-tag">KNOWN PATTERNS</span>
            <h3>Does the input resemble phishing characteristics represented in learned data?</h3>
            <p>Known-pattern classification is one part of the intended research.</p>
          </article>
          <article className="question-item">
            <span className="question-number">02</span><span className="question-tag">NOVEL PATTERNS</span>
            <h3>Does the input exhibit characteristics that differ from known patterns?</h3>
            <p>Novelty and anomaly investigation is a planned analysis layer.</p>
          </article>
        </div>
      </section>

      <section className="pipeline-section" aria-labelledby="pipeline-title">
        <div className="section-heading pipeline-heading">
          <span className="section-index">03 / ANALYSIS MODEL</span>
          <h2 id="pipeline-title">A structured path from input to explanation.</h2>
        </div>
        <ol className="pipeline-list">
          {stages.map((stage, index) => (
            <li key={stage}><span className="pipeline-number">{String(index + 1).padStart(2, '0')}</span><span>{stage}</span></li>
          ))}
        </ol>
      </section>

      <section className="sources-section" aria-labelledby="sources-title">
        <div className="section-heading">
          <span className="section-index">04 / INPUT SOURCES</span>
          <h2 id="sources-title">One research direction. Three kinds of signal.</h2>
        </div>
        <div className="source-grid">
          <article className="source-item"><span className="source-mark">01</span><h3>URL</h3><p>Inspect lexical and structural characteristics.</p></article>
          <article className="source-item"><span className="source-mark">02</span><h3>WEBSITE</h3><p>Evaluate structural and content-level signals.</p></article>
          <article className="source-item"><span className="source-mark">03</span><h3>EMAIL</h3><p>Examine message and contextual indicators.</p></article>
        </div>
      </section>

      <section className="positioning-section" aria-labelledby="positioning-title">
        <div className="positioning-copy">
          <span className="section-index">05 / WHY THIS RESEARCH</span>
          <h2 id="positioning-title">Phishing does not remain still.</h2>
          <p>Threats evolve, and systems shaped by previously represented patterns may encounter unfamiliar variations. This project studies known-pattern classification alongside novelty and anomaly investigation.</p>
        </div>
        <div className="positioning-formula" aria-label="Known-pattern classification plus novelty and anomaly investigation">
          <span>KNOWN-PATTERN<br />CLASSIFICATION</span><b aria-hidden="true">+</b><span>NOVELTY / ANOMALY<br />INVESTIGATION</span>
        </div>
      </section>

      <section className="closing-cta" aria-labelledby="cta-title">
        <div><span className="section-index">CONTINUE TO THE WORKSPACE</span><h2 id="cta-title">Ready to examine a signal?</h2><p>Start with a URL, website, or email.</p></div>
        <button className="button button-primary" type="button" onClick={() => onAnalyze('url')}>OPEN ANALYZER <span aria-hidden="true">↗</span></button>
      </section>
    </>
  )
}
