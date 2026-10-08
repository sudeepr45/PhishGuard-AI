import { useEffect, useState } from 'react'
import { AppShell } from './components/layout/AppShell'
import { AboutPage } from './pages/AboutPage'
import { AnalyzePage } from './pages/AnalyzePage'
import { HistoryPage } from './pages/HistoryPage'
import { HomePage } from './pages/HomePage'
import './App.css'

function currentPath() {
  return window.location.pathname.replace(/\/$/, '') || '/'
}

function App() {
  const [path, setPath] = useState(currentPath)

  useEffect(() => {
    const onPopState = () => setPath(currentPath())
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  function navigate(to: string) {
    if (to === path) return
    window.history.pushState({}, '', to)
    setPath(currentPath())
    window.scrollTo({ top: 0, behavior: 'instant' })
  }

  const page = path === '/analyze'
    ? <AnalyzePage />
    : path === '/history'
      ? <HistoryPage />
      : path === '/about'
        ? <AboutPage />
        : <HomePage onAnalyze={(mode) => navigate(`/analyze?type=${mode}`)} />

  return <AppShell currentPath={path} navigate={navigate}>{page}</AppShell>
}

export default App
