export function AboutPage() {
  return (
    <section className="placeholder-page about-page" aria-labelledby="about-title">
      <div className="eyebrow"><span className="eyebrow-line" /> PHISHGUARD AI / PROJECT</div>
      <p className="kicker">ABOUT THE PROJECT</p>
      <h1 id="about-title">What the system does today.</h1>
      <p className="page-lede">PhishGuard AI is a local research prototype. It classifies canonical URL text, explains the Logistic Regression logit mathematically, and reports a separate structural novelty result.</p>

      <div className="about-grid">
        <article><span className="section-index">DATASET</span><h2>UCI PhiUSIIL</h2><p>Training uses URL values and labels from the UCI PhiUSIIL Phishing URL (Website) Dataset. The pipeline ignores its precomputed webpage features and derives inputs only from each URL string.</p></article>
        <article><span className="section-index">RUNTIME INPUTS</span><h2>17 URL-string features</h2><p>Measurements describe URL length, hostname structure, characters, path, query, and fragment. The service never fetches a URL or inspects webpage content.</p></article>
        <article><span className="section-index">SELECTED MODEL</span><h2>Logistic Regression</h2><p>Version url-classifier-3 uses class-balanced Logistic Regression with StandardScaler. It returns uncalibrated class scores and per-feature contributions that reconstruct its phishing logit.</p></article>
        <article><span className="section-index">SEPARATE EXPERIMENTAL SIGNAL</span><h2>Isolation Forest novelty</h2><p>Version url-novelty-1 measures structural unusualness relative to legitimate training URLs. Novelty is separate from the phishing prediction and is not evidence of intent.</p></article>
        <article><span className="section-index">EXTERNAL EVALUATION</span><h2>Domain-disjoint corpus</h2><p>On the retained Mendeley external set, the classifier's phishing recall was 0.9968 but its legitimate false-positive rate was 0.8619. The novelty detector's ROC-AUC was 0.4413. These poor results and the source-lineage limitation are documented in the external evaluation report.</p></article>
        <article><span className="section-index">LOCAL HISTORY</span><h2>Stored on this device</h2><p>Completed analyses are saved in a local SQLite database for the History page. Individual records or all history can be deleted from that page; no history is transmitted to an external service.</p></article>
        <article><span className="section-index">TRANSIENT EMAIL TRIAGE</span><h2>Parse and screen links offline</h2><p>Pasted email headers are parsed locally, and supported HTTP(S) links in plain text and HTML href attributes are screened with the URL models. The email is not classified or saved. Authentication headers are not verified.</p></article>
        <article><span className="section-index">NOT IMPLEMENTED</span><h2>Live site and sender verification</h2><p>No page fetching, DOM inspection, reputation lookup, real-time threat intelligence, SPF/DKIM/DMARC verification, or trained email classifier is provided.</p></article>
      </div>

      <p className="about-caveat">Classifier scores are uncalibrated, and contribution values are mathematical terms in the model logit, not causal explanations. The external results show limited performance on this dataset and do not establish broad generalization. No output guarantees that a URL is safe or malicious.</p>
    </section>
  )
}
