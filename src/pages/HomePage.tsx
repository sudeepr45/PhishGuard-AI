import { AnalysisInput, type InputMode } from '../components/home/AnalysisInput'
import { ResearchSections } from '../components/home/ResearchSections'

type HomePageProps = {
  onAnalyze: (mode: InputMode) => void
}

export function HomePage({ onAnalyze }: HomePageProps) {
  return (
    <div className="home-page home-page-full">
      <div className="eyebrow"><span className="eyebrow-line" /> SECURITY RESEARCH / 01</div>
      <section className="home-hero editorial-hero" aria-labelledby="home-title">
        <div className="hero-copy">
          <p className="kicker">MULTI-SOURCE PHISHING ANALYSIS</p>
          <h1 id="home-title">DETECT THE SIGNAL<br />BEHIND THE THREAT.</h1>
          <p className="hero-description">AI-powered phishing analysis across URLs, websites, and emails, designed to identify known threats and investigate patterns that may fall outside what a model has seen before.</p>
        </div>
        <AnalysisInput onSubmit={onAnalyze} />
      </section>
      <ResearchSections onAnalyze={onAnalyze} />
    </div>
  )
}
