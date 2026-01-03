import { Theme } from '../theme'
import { routeHref } from '../api'

interface FooterProps {
  theme: Theme
}

export function Footer({ theme }: FooterProps) {
  return (
    <footer className="mt-12 pt-6 border-t text-center text-sm" style={{ borderTopColor: theme.border, color: theme.textSubtle }}>
      <div className="mb-2 text-[13px]" style={{ color: theme.textMuted }}>
        Your personal social data platform
      </div>
      <div className="mb-3">
        <a href={routeHref('/docs')} className="no-underline mx-3" style={{ color: theme.textMuted }}>About</a>
        <a href={routeHref('/docs/api')} className="no-underline mx-3" style={{ color: theme.textMuted }}>API</a>
        <a href={routeHref('/docs/deployment')} className="no-underline mx-3" style={{ color: theme.textMuted }}>Deploy</a>
        <a href="https://github.com/russellromney/tenant.social" target="_blank" rel="noopener noreferrer" className="no-underline mx-3" style={{ color: theme.textMuted }}>GitHub</a>
      </div>
      Made with ❤️ in NYC by <a href="https://russellromney.com" target="_blank" rel="noopener noreferrer" className="no-underline" style={{ color: theme.link }}>me</a>
    </footer>
  )
}
