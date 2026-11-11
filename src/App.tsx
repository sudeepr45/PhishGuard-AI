import { useEffect, useState } from 'react'
import { AppShell } from './components/layout/AppShell'
import { AboutPage } from './pages/AboutPage'
import { AnalyzePage } from './pages/AnalyzePage'
import { HistoryPage } from './pages/HistoryPage'
import { HomePage } from './pages/HomePage'
import { analyzeUrl, type UrlAnalysis } from './services/urlAnalysis'
import './App.css'

function currentPath() {
  return window.location.pathname.replace(/\/$/, '') || '/'
}

function App() {
  const [path, setPath] = useState(currentPath)
  const [initialUrl, setInitialUrl] = useState('')
  const [initialResult, setInitialResult] = useState<UrlAnalysis | null>(null)

  useEffect(() => {
    const onPopState = () => {
      const nextPath = currentPath()
      setPath(nextPath)
      if (!nextPath.startsWith('/analyze')) {
        setInitialUrl('')
        setInitialResult(null)
      }
    }
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  function navigate(to: string) {
    if (to === path) return
    if (!to.startsWith('/analyze')) {
      setInitialUrl('')
      setInitialResult(null)
    }
    window.history.pushState({}, '', to)
    setPath(currentPath())
    window.scrollTo({ top: 0, behavior: 'instant' })
  }

  const historyMatch = path.match(/^\/history\/(\d+)$/)
  const page = path === '/analyze'
    ? <AnalyzePage initialUrl={initialUrl} initialResult={initialResult ?? undefined} />
    : path === '/history' || historyMatch
      ? <HistoryPage analysisId={historyMatch ? Number(historyMatch[1]) : undefined} navigate={navigate} />
      : path === '/about'
        ? <AboutPage />
        : <HomePage onAnalyze={async (mode, value) => {
            if (mode !== 'url' || !value) return
            const response = await analyzeUrl(value)
            setInitialUrl(value)
            setInitialResult(response)
            navigate('/analyze')
          }} />

  return <AppShell currentPath={path} navigate={navigate}>{page}</AppShell>
}

export default App
