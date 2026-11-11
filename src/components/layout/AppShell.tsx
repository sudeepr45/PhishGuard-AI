import type { ReactNode } from 'react'
import { PUBLIC_DEMO_MODE } from '../../runtimeConfig'

const links = [
  { label: 'Home', href: '/' },
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
            {links.filter(({ href }) => !PUBLIC_DEMO_MODE || href !== '/history').map(({ label, href }) => (
              <a key={href} href={href} onClick={(event) => handleNavigation(event, href)}
                className={currentPath === href || (href === '/' && currentPath === '/') || (href === '/history' && currentPath.startsWith('/history/')) ? 'nav-link active' : 'nav-link'}
                aria-current={currentPath === href || (href === '/' && currentPath === '/') || (href === '/history' && currentPath.startsWith('/history/')) ? 'page' : undefined}>
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
          <span className="footer-note">A URL classification research prototype</span>
          <span className="footer-state"><i aria-hidden="true" /> PHASE A MODEL</span>
        </div>
      </footer>
    </div>
  )
}
