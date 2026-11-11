import { AnalysisInput, type InputMode } from '../components/home/AnalysisInput'
import { PUBLIC_DEMO_MODE } from '../runtimeConfig'

type HomePageProps = {
  onAnalyze: (mode: InputMode, value?: string) => Promise<void>
}

export function HomePage({ onAnalyze }: HomePageProps) {
  return (
    <div className="home-page">
      <div className="eyebrow"><span className="eyebrow-line" /> PHISHGUARD AI / URL CLASSIFICATION</div>
      <section className="home-hero editorial-hero" aria-labelledby="home-title">
        <div className="hero-copy">
          <p className="kicker">URL SECURITY ANALYSIS · PHASE A</p>
          <h1 id="home-title">Understand the URL.<br /><span>See the evidence.</span></h1>
          <p className="hero-description">PhishGuard AI uses a selected machine-learning model to classify URL text as phishing or legitimate, then shows the model scores and 17 measurements extracted from that URL.</p>
        </div>
        <AnalysisInput onSubmit={onAnalyze} />
      </section>
      <section className="home-info" aria-label="Analysis scope">
        <article><h2>URL text only</h2><p>The submitted string is analyzed without opening the destination or reading its page.</p></article>
        {PUBLIC_DEMO_MODE
          ? <article><h2>Not saved</h2><p>Public demo analyses are processed for this request only and are not retained.</p></article>
          : <article><h2>Saved locally</h2><p>Completed results are stored in the local SQLite history and can be cleared from the History page.</p></article>}
        <article><h2>Research prototype</h2><p>Scores are uncalibrated model outputs. A legitimate prediction is not proof that a destination is safe.</p></article>
      </section>
    </div>
  )
}
