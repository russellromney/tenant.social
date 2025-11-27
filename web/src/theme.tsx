import { createContext } from 'preact'
import { useContext, useState, useEffect } from 'preact/hooks'

// Color palette definitions
export const lightTheme = {
  // Backgrounds
  bg: '#fafafa',
  bgCard: '#ffffff',
  bgHover: '#f5f5f5',
  bgMuted: '#f0f0f0',
  bgSubtle: '#f9f9f9',
  bgInput: '#ffffff',
  bgToolbar: '#fafafa',

  // Borders
  border: '#eee',
  borderInput: '#ddd',
  borderStrong: '#e5e5e5',

  // Text
  text: '#1a1a1a',
  textSecondary: '#333',
  textMuted: '#666',
  textSubtle: '#999',
  textDisabled: '#ccc',

  // Accents
  accent: '#1a1a1a',
  accentText: '#ffffff',
  link: '#0ea5e9',

  // States
  error: '#e44',
  errorBg: '#fee',
  errorText: '#c44',
  warning: '#fef3c7',
  warningText: '#92400e',
  success: '#dcfce7',
  successText: '#166534',

  // Overlays
  overlay: 'rgba(0,0,0,0.5)',
  shadow: 'rgba(0,0,0,0.1)',
  shadowStrong: 'rgba(0,0,0,0.15)',
}

export const darkTheme = {
  // Backgrounds
  bg: '#0f0f0f',
  bgCard: '#1a1a1a',
  bgHover: '#252525',
  bgMuted: '#2a2a2a',
  bgSubtle: '#222222',
  bgInput: '#1a1a1a',
  bgToolbar: '#161616',

  // Borders
  border: '#333',
  borderInput: '#444',
  borderStrong: '#3a3a3a',

  // Text
  text: '#f0f0f0',
  textSecondary: '#d0d0d0',
  textMuted: '#999',
  textSubtle: '#777',
  textDisabled: '#555',

  // Accents
  accent: '#ffffff',
  accentText: '#1a1a1a',
  link: '#38bdf8',

  // States
  error: '#f87171',
  errorBg: '#3f1d1d',
  errorText: '#f87171',
  warning: '#422006',
  warningText: '#fcd34d',
  success: '#052e16',
  successText: '#4ade80',

  // Overlays
  overlay: 'rgba(0,0,0,0.7)',
  shadow: 'rgba(0,0,0,0.3)',
  shadowStrong: 'rgba(0,0,0,0.5)',
}

export type Theme = typeof lightTheme

interface ThemeContextValue {
  theme: Theme
  isDark: boolean
  toggleTheme: () => void
}

const ThemeContext = createContext<ThemeContextValue | null>(null)

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext)
  if (!ctx) {
    throw new Error('useTheme must be used within ThemeProvider')
  }
  return ctx
}

export function ThemeProvider({ children }: { children: preact.ComponentChildren }) {
  const [isDark, setIsDark] = useState(() => {
    // Check localStorage first
    const saved = localStorage.getItem('tenant-theme')
    if (saved) return saved === 'dark'
    // Fall back to system preference
    return window.matchMedia('(prefers-color-scheme: dark)').matches
  })

  useEffect(() => {
    localStorage.setItem('tenant-theme', isDark ? 'dark' : 'light')
    // Also update document for potential CSS variables or body class usage
    document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light')
  }, [isDark])

  // Listen for system theme changes
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
    const handler = (e: MediaQueryListEvent) => {
      // Only auto-switch if user hasn't set a preference
      const saved = localStorage.getItem('tenant-theme')
      if (!saved) {
        setIsDark(e.matches)
      }
    }
    mediaQuery.addEventListener('change', handler)
    return () => mediaQuery.removeEventListener('change', handler)
  }, [])

  const value: ThemeContextValue = {
    theme: isDark ? darkTheme : lightTheme,
    isDark,
    toggleTheme: () => setIsDark(d => !d),
  }

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  )
}
