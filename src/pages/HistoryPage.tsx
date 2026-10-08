export function HistoryPage() {
  return (
    <section className="placeholder-page" aria-labelledby="history-title">
      <div className="eyebrow"><span className="eyebrow-line" /> RECORDS / 02</div>
      <p className="kicker">RESEARCH RECORDS</p>
      <h1 id="history-title">Analysis history.</h1>
      <p className="page-lede">A future space for reviewing saved analysis sessions and their explanations.</p>
      <div className="empty-state"><span className="empty-icon" aria-hidden="true">⌁</span><h2>No analysis records</h2><p>History will appear here when analysis sessions are supported.</p><span className="mono empty-meta">RECORD STORE / NOT CONNECTED</span></div>
    </section>
  )
}
