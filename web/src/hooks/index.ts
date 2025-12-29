import { useState, useEffect } from 'preact/hooks'
import { getRoute } from '../api'

// Path-based routing hook
export function useRoute() {
  const [route, setRoute] = useState(getRoute())

  useEffect(() => {
    const handleRouteChange = () => setRoute(getRoute())
    window.addEventListener('popstate', handleRouteChange)
    return () => window.removeEventListener('popstate', handleRouteChange)
  }, [])

  return route
}

// Hook for detecting mobile screen size
export function useIsMobile(breakpoint = 640) {
  const [isMobile, setIsMobile] = useState(window.innerWidth < breakpoint)

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth < breakpoint)
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [breakpoint])

  return isMobile
}
