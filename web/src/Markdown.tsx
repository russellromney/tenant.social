import MarkdownIt from 'markdown-it'
import { useMemo } from 'preact/hooks'
import { Theme } from './theme.tsx'

// Configure markdown-it with security settings (no raw HTML)
const md = new MarkdownIt({
  html: false,        // Disable HTML tags in source
  breaks: true,       // Convert \n to <br>
  linkify: true,      // Auto-convert URLs to links
  typographer: true,  // Enable smart quotes and other typographic replacements
})

// Make links open in new tab
const defaultRender = md.renderer.rules.link_open || function(tokens, idx, options, _env, self) {
  return self.renderToken(tokens, idx, options)
}

md.renderer.rules.link_open = function(tokens, idx, options, env, self) {
  tokens[idx].attrSet('target', '_blank')
  tokens[idx].attrSet('rel', 'noopener noreferrer')
  return defaultRender(tokens, idx, options, env, self)
}

interface MarkdownProps {
  content: string
  theme: Theme
  className?: string
}

export function Markdown({ content, theme, className }: MarkdownProps) {
  const html = useMemo(() => md.render(content), [content])

  return (
    <div
      className={className}
      style={{
        // Markdown content styles
        lineHeight: 1.6,
        color: theme.text,
      }}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  )
}
