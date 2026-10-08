export function AboutPage() {
  return (
    <section className="placeholder-page about-page" aria-labelledby="about-title">
      <div className="eyebrow"><span className="eyebrow-line" /> PROJECT / 03</div>
      <p className="kicker">ABOUT THE PROJECT</p>
      <h1 id="about-title">Researching phishing<br />from multiple angles.</h1>
      <p className="page-lede">PhishGuard AI is a university major project investigating a structured approach to phishing analysis across different sources.</p>
      <div className="about-grid">
        <article><span className="section-index">01 — CLASSIFICATION</span><h2>Known patterns</h2><p>Explore how established phishing indicators can inform classification.</p></article>
        <article><span className="section-index">02 — NOVELTY</span><h2>Unfamiliar patterns</h2><p>Investigate how anomaly and novelty detection may help surface less familiar behavior.</p></article>
      </div>
      <p className="about-caveat">These are research directions. No model or detection capability is implemented in this phase.</p>
    </section>
  )
}
