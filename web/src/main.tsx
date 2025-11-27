import { render } from 'preact'
import App from './App'
import { ThemeProvider } from './theme.tsx'

render(
  <ThemeProvider>
    <App />
  </ThemeProvider>,
  document.getElementById('root')!
)
