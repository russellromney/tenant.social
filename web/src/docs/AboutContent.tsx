import { Theme } from '../theme'

export function AboutContent({ theme }: { theme: Theme }) {
  return (
    <div style={{ lineHeight: 1.7, color: theme.textSecondary }}>
      <p style={{ fontSize: 18, marginBottom: 24 }}>
        <strong>Tenant</strong> is your personal social data platform. Own your data, your way.
      </p>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>What is Tenant?</h3>
      <p>
        Tenant combines the best parts of Twitter and Notion—without the creepy parts.
        It's open source, highly extensible, and puts you in control.
      </p>

      <ul style={{ marginTop: 16, paddingLeft: 24 }}>
        <li><strong>Store anything</strong> — Notes, links, tasks, bookmarks, photos, anything</li>
        <li><strong>Your own schema</strong> — Define custom types (Kinds) with your own attributes</li>
        <li><strong>Social features</strong> — Follow other Tenant users, share with friends or publicly</li>
        <li><strong>API-first</strong> — Full REST API with granular scopes for integrations</li>
        <li><strong>Version history</strong> — Never lose data, track every change</li>
        <li><strong>Cheap to run</strong> — Single binary, SQLite or Turso, minimal resources</li>
      </ul>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Social Features</h3>
      <p>Tenant supports social interactions between instances:</p>
      <ul style={{ marginTop: 16, paddingLeft: 24 }}>
        <li><strong>Visibility</strong> — Mark things as private, friends-only, or public</li>
        <li><strong>Follow users</strong> — Follow other Tenant users to see their shared content</li>
        <li><strong>Friend feed</strong> — See things from people you follow in one place</li>
        <li><strong>Public profiles</strong> — Share your public things with anyone</li>
      </ul>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Philosophy</h3>
      <p>
        Social platforms have become creepy data extractors. Notion-like tools are great but don't feel social.
        Tenant is different:
      </p>
      <ul style={{ marginTop: 16, paddingLeft: 24 }}>
        <li><strong>Single tenant</strong> — One owner per instance. Your data, your server.</li>
        <li><strong>Open source</strong> — See exactly what's running. Modify it how you like.</li>
        <li><strong>Extensible</strong> — API keys with granular scopes let you build integrations</li>
        <li><strong>Not creepy</strong> — No ads, no tracking, no selling your data</li>
      </ul>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Links</h3>
      <ul style={{ paddingLeft: 24 }}>
        <li><a href="https://github.com/russellromney/tenant.social" style={{ color: theme.link }}>GitHub Repository</a></li>
        <li><a href="https://tenant.social" style={{ color: theme.link }}>Sandbox (try it out)</a></li>
      </ul>
    </div>
  )
}
