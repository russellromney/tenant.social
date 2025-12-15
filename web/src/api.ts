// Known app routes - used to distinguish routes from base path
const APP_ROUTES = ['/', '/feed', '/friends', '/settings', '/kinds', '/data', '/keys', '/about', '/docs', '/guides', '/login', '/post']

// Get the base path for API calls (e.g., '/sandbox' from '/sandbox/friends')
// This allows the frontend to work both standalone and under apartment's /{username} prefix
export function getBasePath(): string {
  const path = window.location.pathname
  const segments = path.split('/').filter(Boolean)

  // If no segments or first segment is a known route, base is empty
  if (segments.length === 0) return ''

  const firstSegment = '/' + segments[0]
  if (APP_ROUTES.includes(firstSegment) || firstSegment.startsWith('/post')) {
    return ''
  }

  // First segment is the base path (username)
  return '/' + segments[0]
}

// Get the current route from pathname (excluding base path)
export function getRoute(): string {
  const path = window.location.pathname
  const base = getBasePath()

  // Remove base path from pathname
  let route = base ? path.slice(base.length) : path

  // Ensure route starts with /
  if (!route || route === '') route = '/'
  if (!route.startsWith('/')) route = '/' + route

  return route
}

// Navigate to a route (handles base path automatically)
export function navigateTo(route: string): void {
  const base = getBasePath()
  const fullPath = base + (route.startsWith('/') ? route : '/' + route)
  window.history.pushState({}, '', fullPath)
  window.dispatchEvent(new PopStateEvent('popstate'))
}

// Helper to build API URLs with the correct base path
export function apiUrl(endpoint: string): string {
  const base = getBasePath()
  // Ensure endpoint starts with /
  if (!endpoint.startsWith('/')) {
    endpoint = '/' + endpoint
  }
  return base + endpoint
}

// Build a link href with the correct base path
export function routeHref(route: string): string {
  const base = getBasePath()
  return base + (route.startsWith('/') ? route : '/' + route)
}

// Setup global click handler for client-side navigation
// Call this once at app startup
export function setupClientSideNavigation(): void {
  document.addEventListener('click', (e) => {
    const target = e.target as HTMLElement
    const anchor = target.closest('a')

    if (!anchor) return

    const href = anchor.getAttribute('href')
    if (!href) return

    // Skip external links, anchors, and links that open in new tab
    if (href.startsWith('http') || href.startsWith('#') || href.startsWith('mailto:') ||
        anchor.target === '_blank' || anchor.hasAttribute('download')) {
      return
    }

    // Skip if modifier keys are pressed (user wants to open in new tab)
    if (e.ctrlKey || e.metaKey || e.shiftKey) return

    // Handle internal navigation
    e.preventDefault()

    const base = getBasePath()
    let route = href

    // If href starts with base, extract the route part
    if (base && href.startsWith(base)) {
      route = href.slice(base.length) || '/'
    }

    navigateTo(route)
  })
}
