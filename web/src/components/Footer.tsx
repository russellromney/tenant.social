import { Theme } from '../theme'
import { routeHref } from '../api'

interface FooterProps {
  theme: Theme
}

export function Footer({ theme }: FooterProps) {
  return (
    <footer style={{
      marginTop: 48,
      paddingTop: 24,
      borderTop: `1px solid ${theme.border}`,
      textAlign: 'center',
      color: theme.textSubtle,
      fontSize: 14,
    }}>
      <div style={{ marginBottom: 8, color: theme.textMuted, fontSize: 13 }}>
        Your personal social data platform
      </div>
      <div style={{ marginBottom: 12 }}>
        <a href={routeHref('/docs')} style={{ color: theme.textMuted, textDecoration: 'none', margin: '0 12px' }}>About</a>
        <a href={routeHref('/docs/api')} style={{ color: theme.textMuted, textDecoration: 'none', margin: '0 12px' }}>API</a>
        <a href={routeHref('/docs/deployment')} style={{ color: theme.textMuted, textDecoration: 'none', margin: '0 12px' }}>Deploy</a>
        <a href="https://github.com/russellromney/tenant.social" target="_blank" rel="noopener noreferrer" style={{ color: theme.textMuted, textDecoration: 'none', margin: '0 12px' }}>GitHub</a>
      </div>
      Made with ❤️ in NYC by <a href="https://russellromney.com" target="_blank" rel="noopener noreferrer" style={{ color: theme.link, textDecoration: 'none' }}>me</a>
    </footer>
  )
}
