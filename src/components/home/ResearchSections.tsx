import type { InputMode } from './AnalysisInput'

const stages = ['URL INPUT', 'FEATURES', 'CLASSIFIER', 'PREDICTION', 'EVIDENCE', 'SCOPE']

type ResearchSectionsProps = {
  onAnalyze: (mode: InputMode, value?: string) => void
}

export function ResearchSections({ onAnalyze }: ResearchSectionsProps) {
  return (
    <>
      <section className="research-questions" aria-labelledby="questions-title">
        <div className="section-heading">
          <span className="section-index">02 / RESEARCH DIRECTION</span>
          <h2 id="questions-title">Two separate model outputs.</h2>
          <p>A supervised phishing prediction and a structural novelty indicator are returned independently.</p>
        </div>
        <div className="question-grid">
          <article className="question-item">
            <span className="question-number">01</span><span className="question-tag">KNOWN PATTERNS</span>
            <h3>Does the input resemble phishing characteristics represented in learned data?</h3>
            <p>The selected Logistic Regression model returns a phishing or legitimate prediction with mathematical feature contributions.</p>
          </article>
          <article className="question-item">
            <span className="question-number">02</span><span className="question-tag">NOVEL PATTERNS</span>
            <h3>Does the input exhibit characteristics that differ from known patterns?</h3>
            <p>The separate Isolation Forest flags structural unusualness. It is experimental and does not determine the phishing prediction.</p>
          </article>
        </div>
      </section>

      <section className="pipeline-section" aria-labelledby="pipeline-title">
        <div className="section-heading pipeline-heading">
          <span className="section-index">03 / ANALYSIS MODEL</span>
          <h2 id="pipeline-title">The URL classifier workflow.</h2>
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
          <h2 id="sources-title">Implemented inputs and clear boundaries.</h2>
        </div>
        <div className="source-grid">
          <article className="source-item"><span className="source-mark">01</span><h3>URL · AVAILABLE</h3><p>Classify lexical features in URL text without fetching the destination.</p></article>
          <article className="source-item"><span className="source-mark">02</span><h3>EMAIL · TRANSIENT TRIAGE</h3><p>Headers are parsed offline; links from plain text and HTML href values are screened. No email classifier or email history is provided.</p></article>
          <article className="source-item"><span className="source-mark">03</span><h3>WEBPAGE · NOT IMPLEMENTED</h3><p>No destination is fetched and no page content or DOM is inspected.</p></article>
        </div>
      </section>

      <section className="positioning-section" aria-labelledby="positioning-title">
        <div className="positioning-copy">
          <span className="section-index">05 / WHY THIS RESEARCH</span>
          <h2 id="positioning-title">Phishing does not remain still.</h2>
          <p>The project compares a frozen phishing classifier with a separate novelty detector. External evaluation shows a high legitimate false-positive rate for the classifier and below-chance novelty ROC-AUC; these results limit claims about generalization.</p>
        </div>
        <div className="positioning-formula" aria-label="Known-pattern classification plus novelty and anomaly investigation">
          <span>KNOWN-PATTERN<br />CLASSIFICATION</span><b aria-hidden="true">+</b><span>NOVELTY / ANOMALY<br />INVESTIGATION</span>
        </div>
      </section>

      <section className="closing-cta" aria-labelledby="cta-title">
        <div><span className="section-index">CONTINUE TO THE WORKSPACE</span><h2 id="cta-title">Ready to examine a URL?</h2><p>Analyze URL text with the Phase A model.</p></div>
        <button className="button button-primary" type="button" onClick={() => onAnalyze('url')}>OPEN ANALYZER <span aria-hidden="true">↗</span></button>
      </section>
    </>
  )
}
