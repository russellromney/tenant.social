import { render } from 'preact'
import './index.css'
import App from './App'
import { ThemeProvider } from './theme.tsx'

render(
  <ThemeProvider>
    <App />
  </ThemeProvider>,
  document.getElementById('root')!
)
