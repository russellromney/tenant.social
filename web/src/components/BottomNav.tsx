import { Theme } from '../theme'
import { routeHref } from '../api'

interface NavItem {
  href: string
  icon: string
  label: string
  active: boolean
}

interface BottomNavProps {
  items: NavItem[]
  theme: Theme
  onThemeToggle: () => void
  isDark: boolean
}

export function BottomNav({ items, theme, onThemeToggle, isDark }: BottomNavProps) {
  return (
    <nav
      className="fixed bottom-0 left-0 right-0 z-50 flex items-center justify-around border-t safe-area-pb"
      style={{
        background: theme.bgCard,
        borderTopColor: theme.border,
        paddingBottom: 'env(safe-area-inset-bottom, 0px)',
      }}
    >
      {items.map(item => (
        <a
          key={item.href}
          href={routeHref(item.href)}
          className="flex flex-col items-center justify-center py-2 px-3 no-underline min-w-[64px]"
          style={{
            color: item.active ? theme.accent : theme.textMuted,
          }}
        >
          <span className="text-xl mb-0.5">{item.icon}</span>
          <span className="text-[10px] font-medium">{item.label}</span>
        </a>
      ))}
      <button
        onClick={onThemeToggle}
        className="flex flex-col items-center justify-center py-2 px-3 bg-transparent border-0 min-w-[64px]"
        style={{ color: theme.textMuted }}
      >
        <span className="text-xl mb-0.5">{isDark ? '☀️' : '🌙'}</span>
        <span className="text-[10px] font-medium">Theme</span>
      </button>
    </nav>
  )
}
