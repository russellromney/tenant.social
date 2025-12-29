import { Theme } from '../theme'

export function DeploymentContent({ theme }: { theme: Theme }) {
  return (
    <div style={{ lineHeight: 1.7, color: theme.textSecondary }}>
      <p style={{ marginBottom: 24 }}>
        Deploy your own Tenant instance in minutes. Choose your preferred platform:
      </p>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Fly.io (Recommended)</h3>
      <p>Easiest deployment with automatic HTTPS and global edge network.</p>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`# Install Fly CLI
curl -L https://fly.io/install.sh | sh

# Clone and deploy
git clone https://github.com/russellromney/tenant.social.git
cd tenant.social

# Create app and volume
fly apps create my-tenant
fly volumes create tenant_data --size 1 --region ewr

# Deploy
fly deploy

# Visit https://my-tenant.fly.dev`}
      </pre>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Docker</h3>
      <p>Run anywhere Docker runs.</p>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`# Build
docker build -t tenant .

# Run with persistent data
docker run -d \\
  -p 8080:8080 \\
  -v tenant_data:/data \\
  -e PRODUCTION=true \\
  -e DB_BACKEND=sqlite \\
  -e SQLITE_PATH=/data/tenant.db \\
  tenant`}
      </pre>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Run Locally</h3>
      <p>For development or personal use on your machine.</p>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`# Clone
git clone https://github.com/russellromney/tenant.social.git
cd tenant.social

# Install frontend dependencies
cd web && npm install && cd ..

# Run (uses local SQLite)
make dev

# Visit http://localhost:3069`}
      </pre>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Turso (Cloud Database)</h3>
      <p>Use Turso for edge-replicated SQLite in the cloud.</p>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`# Create Turso database
turso db create tenant

# Get credentials
turso db show tenant --url
turso db tokens create tenant

# Set environment variables
DB_BACKEND=turso
TURSO_DATABASE_URL=libsql://tenant-xxx.turso.io
TURSO_AUTH_TOKEN=your-token`}
      </pre>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Environment Variables</h3>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 14 }}>
        <thead>
          <tr style={{ borderBottom: `2px solid ${theme.borderInput}` }}>
            <th style={{ textAlign: 'left', padding: '8px 0' }}>Variable</th>
            <th style={{ textAlign: 'left', padding: '8px 0' }}>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr style={{ borderBottom: `1px solid ${theme.border}` }}>
            <td style={{ padding: '8px 0' }}><code>PORT</code></td>
            <td style={{ padding: '8px 0' }}>Server port (default: 8069)</td>
          </tr>
          <tr style={{ borderBottom: `1px solid ${theme.border}` }}>
            <td style={{ padding: '8px 0' }}><code>PRODUCTION</code></td>
            <td style={{ padding: '8px 0' }}>Set to "true" for production mode</td>
          </tr>
          <tr style={{ borderBottom: `1px solid ${theme.border}` }}>
            <td style={{ padding: '8px 0' }}><code>DB_BACKEND</code></td>
            <td style={{ padding: '8px 0' }}>"sqlite" or "turso"</td>
          </tr>
          <tr style={{ borderBottom: `1px solid ${theme.border}` }}>
            <td style={{ padding: '8px 0' }}><code>SQLITE_PATH</code></td>
            <td style={{ padding: '8px 0' }}>Path to SQLite database file</td>
          </tr>
          <tr style={{ borderBottom: `1px solid ${theme.border}` }}>
            <td style={{ padding: '8px 0' }}><code>TURSO_DATABASE_URL</code></td>
            <td style={{ padding: '8px 0' }}>Turso database URL</td>
          </tr>
          <tr>
            <td style={{ padding: '8px 0' }}><code>TURSO_AUTH_TOKEN</code></td>
            <td style={{ padding: '8px 0' }}>Turso auth token</td>
          </tr>
        </tbody>
      </table>
    </div>
  )
}
