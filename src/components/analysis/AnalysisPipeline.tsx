const stages = [
  { number: '01', title: 'INPUT', description: 'Source submitted for examination.' },
  { number: '02', title: 'FEATURES', description: 'Lexical, structural, and content signals.' },
  { number: '03', title: 'CLASSIFICATION', description: 'Compare with represented phishing patterns.' },
  { number: '04', title: 'NOVELTY', description: 'Investigate characteristics outside known patterns.' },
  { number: '05', title: 'RISK', description: 'Assess risk from combined evidence.' },
  { number: '06', title: 'EXPLANATION', description: 'Interpret the evidence for a person.' },
]

export function AnalysisPipeline() {
  return (
    <section className="analysis-pipeline" aria-labelledby="pipeline-title">
      <div className="analysis-section-heading">
        <div><span className="section-index">01 / CONCEPTUAL WORKFLOW</span><h2 id="pipeline-title">The planned analysis path</h2></div>
        <span className="pipeline-footnote">ARCHITECTURE PREVIEW</span>
      </div>
      <ol className="analysis-pipeline-list">
        {stages.map(({ number, title, description }) => (
          <li key={number}>
            <span className="pipeline-step-number">{number}</span>
            <h3>{title}</h3>
            <p>{description}</p>
          </li>
        ))}
      </ol>
      <p className="architecture-disclaimer">Planned system architecture · no analysis engine is connected.</p>
    </section>
  )
}
