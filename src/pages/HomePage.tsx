export function HomePage() {
  return (
    <div className="home-page">
      <div className="eyebrow"><span className="eyebrow-line" /> SECURITY RESEARCH / 01</div>
      <section className="home-hero" aria-labelledby="home-title">
        <div className="hero-copy">
          <p className="kicker">MULTI-SOURCE PHISHING ANALYSIS</p>
          <h1 id="home-title">Understand the signals<br />behind <span>deceptive content.</span></h1>
          <p className="hero-description">PhishGuard AI is a research project exploring how known phishing patterns and previously unseen threats can be studied across URLs, websites, and email.</p>
          <a className="button button-primary" href="/analyze">Open analysis workspace <span aria-hidden="true">↗</span></a>
          <p className="prototype-note"><span aria-hidden="true">i</span> Research interface in development. No live analysis is performed.</p>
        </div>
        <div className="signal-panel" aria-label="The research scope covers three input sources">
          <div className="panel-topline"><span>RESEARCH SCOPE</span><span className="mono">PG / 001</span></div>
          <div className="scope-list">
            <div className="scope-row"><span className="scope-index">01</span><span className="scope-name">URL signals</span><span className="scope-type">INPUT</span></div>
            <div className="scope-row"><span className="scope-index">02</span><span className="scope-name">Website signals</span><span className="scope-type">INPUT</span></div>
            <div className="scope-row"><span className="scope-index">03</span><span className="scope-name">Email signals</span><span className="scope-type">INPUT</span></div>
          </div>
          <div className="panel-foot"><span className="scope-dot" /> SYSTEM STATUS</div>
          <p className="panel-caption">Interface foundation · analysis capabilities planned</p>
        </div>
      </section>
      <section className="home-bottom" aria-label="Project principles">
        <div className="bottom-intro"><span className="section-index">01 — APPROACH</span><h2>Two questions.<br />One careful process.</h2></div>
        <article className="principle"><span className="principle-number">A</span><div><h3>Recognize the known</h3><p>Study patterns associated with established phishing techniques.</p></div></article>
        <article className="principle"><span className="principle-number">B</span><div><h3>Investigate the unfamiliar</h3><p>Explore novelty and anomaly analysis for patterns not yet catalogued.</p></div></article>
      </section>
    </div>
  )
}
