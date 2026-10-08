import type { ReactNode } from 'react'

const links = [
  { label: 'Analyze', href: '/analyze' },
  { label: 'History', href: '/history' },
  { label: 'About', href: '/about' },
]

type AppShellProps = {
  children: ReactNode
  currentPath: string
  navigate: (to: string) => void
}

export function AppShell({ children, currentPath, navigate }: AppShellProps) {
  function handleNavigation(event: React.MouseEvent<HTMLAnchorElement>, href: string) {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
    event.preventDefault()
    navigate(href)
  }

  return (
    <div className="app-shell">
      <header className="site-header">
        <div className="header-inner">
          <a className="wordmark" href="/" onClick={(event) => handleNavigation(event, '/')}
            aria-label="PhishGuard AI home">
            <span className="wordmark-mark" aria-hidden="true">P</span>
            <span>PHISHGUARD <span className="wordmark-ai">AI</span></span>
          </a>
          <nav className="primary-nav" aria-label="Main navigation">
            {links.map(({ label, href }) => (
              <a key={href} href={href} onClick={(event) => handleNavigation(event, href)}
                className={currentPath === href ? 'nav-link active' : 'nav-link'}
                aria-current={currentPath === href ? 'page' : undefined}>
                {label}
              </a>
            ))}
          </nav>
        </div>
      </header>
      <main id="main-content" className="page-container">{children}</main>
      <footer className="site-footer">
        <div className="footer-inner">
          <span>PHISHGUARD AI</span>
          <span className="footer-note">A research project in multi-source phishing analysis</span>
          <span className="footer-state"><i aria-hidden="true" /> FRONTEND FOUNDATION</span>
        </div>
      </footer>
    </div>
  )
}
