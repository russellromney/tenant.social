import { useState, useEffect } from 'preact/hooks'
import { Theme } from '../theme'
import { Kind } from '../types'
import { apiUrl } from '../api'

// Webhook types
interface FilterCondition {
  field: string
  op: string
  value: any
}

interface FilterConfig {
  kinds?: string[]
  condition_groups?: FilterCondition[][]
}

interface OutboundWebhook {
  id: string
  name: string
  url: string
  event_types: string[]
  signing_secret?: string
  filter_config?: FilterConfig
  enabled: boolean
  created_at: string
  updated_at: string
}

interface InboundWebhook {
  id: string
  name: string
  source_system: string
  default_thing_type: string
  default_visibility: string
  token_prefix: string
  secret_token?: string
  enabled: boolean
  created_at: string
  updated_at: string
}

interface WebhookTestResult {
  success: boolean
  status_code?: number
  response_time_ms?: number
  error?: string
}

export function IntegrationsPanel({ theme, kinds }: { theme: Theme, kinds: Kind[] }) {
  const [outboundWebhooks, setOutboundWebhooks] = useState<OutboundWebhook[]>([])
  const [inboundWebhooks, setInboundWebhooks] = useState<InboundWebhook[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreateOutbound, setShowCreateOutbound] = useState(false)
  const [showCreateInbound, setShowCreateInbound] = useState(false)
  const [testingWebhook, setTestingWebhook] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<{ id: string, result: WebhookTestResult } | null>(null)
  const [expandedOutbound, setExpandedOutbound] = useState<string | null>(null)
  const [expandedInbound, setExpandedInbound] = useState<string | null>(null)
  const [revealedToken, setRevealedToken] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  useEffect(() => {
    fetchWebhooks()
  }, [])

  async function fetchWebhooks() {
    setLoading(true)
    try {
      const [outboundRes, inboundRes] = await Promise.all([
        fetch(apiUrl('/api/webhooks'), { credentials: 'include' }),
        fetch(apiUrl('/api/webhooks/inbound'), { credentials: 'include' }),
      ])

      if (outboundRes.ok) {
        const data = await outboundRes.json()
        setOutboundWebhooks(Array.isArray(data) ? data : [])
      }

      if (inboundRes.ok) {
        const data = await inboundRes.json()
        setInboundWebhooks(Array.isArray(data) ? data : [])
      }
    } catch (err) {
      console.error('Failed to fetch webhooks:', err)
    } finally {
      setLoading(false)
    }
  }

  async function toggleOutboundEnabled(webhook: OutboundWebhook) {
    try {
      const res = await fetch(apiUrl(`/api/webhooks/${webhook.id}`), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ enabled: !webhook.enabled }),
      })
      if (res.ok) {
        setOutboundWebhooks(prev => prev.map(w =>
          w.id === webhook.id ? { ...w, enabled: !w.enabled } : w
        ))
      }
    } catch (err) {
      console.error('Failed to toggle webhook:', err)
    }
  }

  async function toggleInboundEnabled(webhook: InboundWebhook) {
    try {
      const res = await fetch(apiUrl(`/api/webhooks/inbound/${webhook.id}`), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ enabled: !webhook.enabled }),
      })
      if (res.ok) {
        setInboundWebhooks(prev => prev.map(w =>
          w.id === webhook.id ? { ...w, enabled: !w.enabled } : w
        ))
      }
    } catch (err) {
      console.error('Failed to toggle webhook:', err)
    }
  }

  async function deleteOutboundWebhook(id: string) {
    if (!confirm('Delete this webhook? This cannot be undone.')) return
    try {
      const res = await fetch(apiUrl(`/api/webhooks/${id}`), {
        method: 'DELETE',
        credentials: 'include',
      })
      if (res.ok) {
        setOutboundWebhooks(prev => prev.filter(w => w.id !== id))
      }
    } catch (err) {
      console.error('Failed to delete webhook:', err)
    }
  }

  async function deleteInboundWebhook(id: string) {
    if (!confirm('Delete this webhook? This cannot be undone.')) return
    try {
      const res = await fetch(apiUrl(`/api/webhooks/inbound/${id}`), {
        method: 'DELETE',
        credentials: 'include',
      })
      if (res.ok) {
        setInboundWebhooks(prev => prev.filter(w => w.id !== id))
      }
    } catch (err) {
      console.error('Failed to delete webhook:', err)
    }
  }

  async function testWebhook(id: string) {
    setTestingWebhook(id)
    setTestResult(null)
    try {
      const start = Date.now()
      const res = await fetch(apiUrl(`/api/webhooks/${id}/test`), {
        method: 'POST',
        credentials: 'include',
      })
      const elapsed = Date.now() - start
      const data = await res.json()
      setTestResult({
        id,
        result: {
          success: res.ok && data.success,
          status_code: data.status_code,
          response_time_ms: elapsed,
          error: data.error,
        }
      })
      // Auto-dismiss after 10 seconds
      setTimeout(() => setTestResult(prev => prev?.id === id ? null : prev), 10000)
    } catch (err) {
      setTestResult({
        id,
        result: { success: false, error: 'Failed to send test' }
      })
    } finally {
      setTestingWebhook(null)
    }
  }

  function copyToClipboard(text: string, id: string) {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const cardStyle = {
    background: theme.bgCard,
    border: `1px solid ${theme.border}`,
    borderRadius: 8,
    padding: 16,
    marginBottom: 12,
  }

  const toggleStyle = (enabled: boolean) => ({
    width: 40,
    height: 22,
    borderRadius: 11,
    background: enabled ? theme.accent : theme.bgMuted,
    border: 'none',
    cursor: 'pointer',
    position: 'relative' as const,
    transition: 'background 0.2s',
  })

  const toggleKnobStyle = (enabled: boolean) => ({
    position: 'absolute' as const,
    top: 2,
    left: enabled ? 20 : 2,
    width: 18,
    height: 18,
    borderRadius: 9,
    background: 'white',
    transition: 'left 0.2s',
  })

  if (loading) {
    return <div style={{ color: theme.textMuted }}>Loading integrations...</div>
  }

  return (
    <div>
      {/* Outbound Webhooks Section */}
      <div style={{ marginBottom: 32 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ margin: 0, color: theme.text, fontSize: 16, fontWeight: 600 }}>
            Outbound Webhooks
          </h3>
          <button
            onClick={() => setShowCreateOutbound(true)}
            style={{
              padding: '6px 12px',
              background: theme.bgHover,
              color: theme.text,
              border: `1px solid ${theme.border}`,
              borderRadius: 6,
              cursor: 'pointer',
              fontSize: 13,
            }}
          >
            + Add
          </button>
        </div>

        {outboundWebhooks.length === 0 ? (
          <div style={{ ...cardStyle, textAlign: 'center', color: theme.textMuted }}>
            No outbound webhooks configured.
            <br />
            <span style={{ fontSize: 13 }}>Outbound webhooks send events to external URLs when things happen.</span>
          </div>
        ) : (
          outboundWebhooks.map(webhook => (
            <div key={webhook.id} style={cardStyle}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <span style={{ fontWeight: 600, color: theme.text }}>
                      {webhook.name || 'Unnamed webhook'}
                    </span>
                    <button
                      onClick={() => toggleOutboundEnabled(webhook)}
                      style={toggleStyle(webhook.enabled)}
                      title={webhook.enabled ? 'Enabled' : 'Disabled'}
                    >
                      <div style={toggleKnobStyle(webhook.enabled)} />
                    </button>
                  </div>
                  <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {webhook.url}
                  </div>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {webhook.event_types?.map(evt => (
                      <span
                        key={evt}
                        style={{
                          fontSize: 11,
                          padding: '2px 8px',
                          background: theme.bgMuted,
                          color: theme.textMuted,
                          borderRadius: 12,
                        }}
                      >
                        {evt}
                      </span>
                    ))}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <button
                    onClick={() => testWebhook(webhook.id)}
                    disabled={testingWebhook === webhook.id}
                    style={{
                      padding: '6px 12px',
                      background: 'transparent',
                      color: theme.accent,
                      border: `1px solid ${theme.accent}`,
                      borderRadius: 4,
                      cursor: testingWebhook === webhook.id ? 'wait' : 'pointer',
                      fontSize: 12,
                      opacity: testingWebhook === webhook.id ? 0.6 : 1,
                    }}
                  >
                    {testingWebhook === webhook.id ? '...' : 'Test'}
                  </button>
                  <button
                    onClick={() => setExpandedOutbound(expandedOutbound === webhook.id ? null : webhook.id)}
                    style={{
                      padding: '6px 10px',
                      background: 'transparent',
                      color: theme.textMuted,
                      border: 'none',
                      cursor: 'pointer',
                      fontSize: 14,
                    }}
                  >
                    {expandedOutbound === webhook.id ? '▲' : '▼'}
                  </button>
                  <button
                    onClick={() => deleteOutboundWebhook(webhook.id)}
                    style={{
                      padding: '6px 10px',
                      background: 'transparent',
                      color: theme.error,
                      border: 'none',
                      cursor: 'pointer',
                      fontSize: 13,
                    }}
                  >
                    Delete
                  </button>
                </div>
              </div>

              {/* Test Result */}
              {testResult?.id === webhook.id && (
                <div
                  style={{
                    marginTop: 12,
                    padding: 12,
                    background: testResult.result.success ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                    borderRadius: 6,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                  }}
                >
                  <span style={{ fontSize: 16 }}>{testResult.result.success ? '✓' : '✗'}</span>
                  <span style={{ fontSize: 13, color: testResult.result.success ? '#22c55e' : theme.error }}>
                    {testResult.result.success
                      ? `Success • ${testResult.result.status_code} • ${testResult.result.response_time_ms}ms`
                      : testResult.result.error || 'Failed'}
                  </span>
                  <button
                    onClick={() => setTestResult(null)}
                    style={{
                      marginLeft: 'auto',
                      background: 'transparent',
                      border: 'none',
                      color: theme.textMuted,
                      cursor: 'pointer',
                      fontSize: 12,
                    }}
                  >
                    Dismiss
                  </button>
                </div>
              )}

              {/* Expanded Details */}
              {expandedOutbound === webhook.id && (
                <div style={{ marginTop: 16, paddingTop: 16, borderTop: `1px solid ${theme.border}` }}>
                  <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 8 }}>
                    <strong>URL:</strong> {webhook.url}
                  </div>
                  {webhook.signing_secret && (
                    <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 8 }}>
                      <strong>Signing Secret:</strong>{' '}
                      <code style={{ background: theme.bgMuted, padding: '2px 6px', borderRadius: 4 }}>
                        {revealedToken === webhook.id ? webhook.signing_secret : '••••••••••••'}
                      </code>
                      <button
                        onClick={() => setRevealedToken(revealedToken === webhook.id ? null : webhook.id)}
                        style={{
                          marginLeft: 8,
                          background: 'transparent',
                          border: 'none',
                          color: theme.accent,
                          cursor: 'pointer',
                          fontSize: 12,
                        }}
                      >
                        {revealedToken === webhook.id ? 'Hide' : 'Reveal'}
                      </button>
                    </div>
                  )}
                  {(webhook.filter_config?.kinds?.length || webhook.filter_config?.condition_groups?.length) && (
                    <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 8 }}>
                      <strong>Filter:</strong>
                      {webhook.filter_config?.kinds?.length && (
                        <span> Kind in [{webhook.filter_config.kinds.join(', ')}]</span>
                      )}
                      {webhook.filter_config?.condition_groups?.length && webhook.filter_config.condition_groups[0]?.length && (
                        <span>
                          {webhook.filter_config.kinds?.length ? ' AND ' : ' '}
                          {webhook.filter_config.condition_groups[0].map((c, i) => (
                            <span key={i}>
                              {i > 0 && ' AND '}
                              {c.field} {c.op} {c.op !== 'exists' ? JSON.stringify(c.value) : ''}
                            </span>
                          ))}
                        </span>
                      )}
                    </div>
                  )}
                  <div style={{ fontSize: 12, color: theme.textMuted }}>
                    Created: {new Date(webhook.created_at).toLocaleDateString()}
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Inbound Webhooks Section */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ margin: 0, color: theme.text, fontSize: 16, fontWeight: 600 }}>
            Inbound Webhooks
          </h3>
          <button
            onClick={() => setShowCreateInbound(true)}
            style={{
              padding: '6px 12px',
              background: theme.bgHover,
              color: theme.text,
              border: `1px solid ${theme.border}`,
              borderRadius: 6,
              cursor: 'pointer',
              fontSize: 13,
            }}
          >
            + Add
          </button>
        </div>

        {inboundWebhooks.length === 0 ? (
          <div style={{ ...cardStyle, textAlign: 'center', color: theme.textMuted }}>
            No inbound webhooks configured.
            <br />
            <span style={{ fontSize: 13 }}>Inbound webhooks let external services create things in your account.</span>
          </div>
        ) : (
          inboundWebhooks.map(webhook => (
            <div key={webhook.id} style={cardStyle}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <span style={{ fontWeight: 600, color: theme.text }}>
                      {webhook.name}
                    </span>
                    <span
                      style={{
                        fontSize: 11,
                        padding: '2px 8px',
                        background: theme.bgMuted,
                        color: theme.textMuted,
                        borderRadius: 12,
                      }}
                    >
                      {webhook.source_system}
                    </span>
                    <button
                      onClick={() => toggleInboundEnabled(webhook)}
                      style={toggleStyle(webhook.enabled)}
                      title={webhook.enabled ? 'Enabled' : 'Disabled'}
                    >
                      <div style={toggleKnobStyle(webhook.enabled)} />
                    </button>
                  </div>
                  <div style={{ fontSize: 13, color: theme.textMuted }}>
                    Creates: {webhook.default_thing_type} ({webhook.default_visibility})
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <button
                    onClick={() => setExpandedInbound(expandedInbound === webhook.id ? null : webhook.id)}
                    style={{
                      padding: '6px 10px',
                      background: 'transparent',
                      color: theme.textMuted,
                      border: 'none',
                      cursor: 'pointer',
                      fontSize: 14,
                    }}
                  >
                    {expandedInbound === webhook.id ? '▲' : '▼'}
                  </button>
                  <button
                    onClick={() => deleteInboundWebhook(webhook.id)}
                    style={{
                      padding: '6px 10px',
                      background: 'transparent',
                      color: theme.error,
                      border: 'none',
                      cursor: 'pointer',
                      fontSize: 13,
                    }}
                  >
                    Delete
                  </button>
                </div>
              </div>

              {/* Expanded Details */}
              {expandedInbound === webhook.id && (
                <div style={{ marginTop: 16, paddingTop: 16, borderTop: `1px solid ${theme.border}` }}>
                  <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 12 }}>
                    <strong>Endpoint:</strong>
                    <div style={{ marginTop: 4, display: 'flex', alignItems: 'center', gap: 8 }}>
                      <code
                        style={{
                          background: theme.bgMuted,
                          padding: '6px 10px',
                          borderRadius: 4,
                          fontSize: 12,
                          wordBreak: 'break-all',
                          flex: 1,
                        }}
                      >
                        POST {window.location.origin}/api/webhooks/receive/{webhook.id}?token=...
                      </code>
                      <button
                        onClick={() => {
                          const url = `${window.location.origin}/api/webhooks/receive/${webhook.id}?token=${webhook.secret_token || webhook.token_prefix + '...'}`
                          copyToClipboard(url, 'url-' + webhook.id)
                        }}
                        style={{
                          padding: '6px 10px',
                          background: theme.bgHover,
                          color: copiedId === 'url-' + webhook.id ? '#22c55e' : theme.text,
                          border: `1px solid ${theme.border}`,
                          borderRadius: 4,
                          cursor: 'pointer',
                          fontSize: 12,
                        }}
                      >
                        {copiedId === 'url-' + webhook.id ? 'Copied!' : 'Copy'}
                      </button>
                    </div>
                  </div>
                  <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 8 }}>
                    <strong>Token:</strong>{' '}
                    <code style={{ background: theme.bgMuted, padding: '2px 6px', borderRadius: 4 }}>
                      {revealedToken === 'inbound-' + webhook.id
                        ? (webhook.secret_token || webhook.token_prefix + '...')
                        : webhook.token_prefix + '••••••••'}
                    </code>
                    <button
                      onClick={() => setRevealedToken(revealedToken === 'inbound-' + webhook.id ? null : 'inbound-' + webhook.id)}
                      style={{
                        marginLeft: 8,
                        background: 'transparent',
                        border: 'none',
                        color: theme.accent,
                        cursor: 'pointer',
                        fontSize: 12,
                      }}
                    >
                      {revealedToken === 'inbound-' + webhook.id ? 'Hide' : 'Reveal'}
                    </button>
                  </div>
                  <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 12 }}>
                    <strong>Example curl:</strong>
                    <pre style={{
                      marginTop: 4,
                      background: theme.bgMuted,
                      padding: 12,
                      borderRadius: 4,
                      fontSize: 11,
                      overflow: 'auto',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all',
                    }}>
{`curl -X POST "${window.location.origin}/api/webhooks/receive/${webhook.id}?token=${webhook.secret_token || 'YOUR_TOKEN'}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "content": "Hello from my automation!",
    "metadata": {
      "source": "zapier",
      "priority": "high"
    },
    "external_id": "unique-123"
  }'`}
                    </pre>
                    <button
                      onClick={() => {
                        const curl = `curl -X POST "${window.location.origin}/api/webhooks/receive/${webhook.id}?token=${webhook.secret_token || 'YOUR_TOKEN'}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"content": "Hello from my automation!", "external_id": "unique-123"}'`
                        copyToClipboard(curl, 'curl-' + webhook.id)
                      }}
                      style={{
                        marginTop: 8,
                        padding: '6px 12px',
                        background: theme.bgHover,
                        color: copiedId === 'curl-' + webhook.id ? '#22c55e' : theme.text,
                        border: `1px solid ${theme.border}`,
                        borderRadius: 4,
                        cursor: 'pointer',
                        fontSize: 12,
                      }}
                    >
                      {copiedId === 'curl-' + webhook.id ? 'Copied!' : 'Copy curl'}
                    </button>
                  </div>
                  <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 8 }}>
                    <strong>Payload fields:</strong>
                    <ul style={{ margin: '8px 0 0 0', paddingLeft: 20, fontSize: 12 }}>
                      <li><code>content</code> - The text content of the Thing (required)</li>
                      <li><code>metadata</code> - Optional JSON object with additional attributes</li>
                      <li><code>external_id</code> - Optional unique ID for deduplication</li>
                    </ul>
                  </div>
                  <div style={{ fontSize: 12, color: theme.textMuted }}>
                    Created: {new Date(webhook.created_at).toLocaleDateString()}
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Create Outbound Modal */}
      {showCreateOutbound && (
        <CreateOutboundWebhookModal
          theme={theme}
          kinds={kinds}
          onClose={() => setShowCreateOutbound(false)}
          onCreate={(webhook) => {
            setOutboundWebhooks(prev => [...prev, webhook])
            setShowCreateOutbound(false)
          }}
        />
      )}

      {/* Create Inbound Modal */}
      {showCreateInbound && (
        <CreateInboundWebhookModal
          theme={theme}
          kinds={kinds}
          onClose={() => setShowCreateInbound(false)}
          onCreate={(webhook) => {
            setInboundWebhooks(prev => [...prev, webhook])
            setShowCreateInbound(false)
            // Show the new webhook expanded to reveal the token
            setExpandedInbound(webhook.id)
            setRevealedToken('inbound-' + webhook.id)
          }}
        />
      )}
    </div>
  )
}

// Create Outbound Webhook Modal
function CreateOutboundWebhookModal({
  theme,
  kinds,
  onClose,
  onCreate,
}: {
  theme: Theme
  kinds: Kind[]
  onClose: () => void
  onCreate: (webhook: OutboundWebhook) => void
}) {
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [eventTypes, setEventTypes] = useState<string[]>(['thing.created'])
  const [filterKinds, setFilterKinds] = useState<string[]>([])
  const [conditions, setConditions] = useState<FilterCondition[]>([])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const availableEvents = [
    { id: 'thing.created', label: 'Thing created' },
    { id: 'thing.updated', label: 'Thing updated' },
    { id: 'thing.deleted', label: 'Thing deleted' },
    { id: 'comment.created', label: 'Comment created' },
  ]

  const operators = [
    { id: 'eq', label: '=' },
    { id: 'neq', label: '≠' },
    { id: 'gt', label: '>' },
    { id: 'gte', label: '≥' },
    { id: 'lt', label: '<' },
    { id: 'lte', label: '≤' },
    { id: 'contains', label: 'contains' },
    { id: 'exists', label: 'exists' },
  ]

  function addCondition() {
    setConditions([...conditions, { field: '', op: 'eq', value: '' }])
  }

  function updateCondition(index: number, updates: Partial<FilterCondition>) {
    setConditions(conditions.map((c, i) => i === index ? { ...c, ...updates } : c))
  }

  function removeCondition(index: number) {
    setConditions(conditions.filter((_, i) => i !== index))
  }

  function parseConditionValue(value: string): any {
    // Try to parse as JSON (number, boolean, etc.)
    try {
      return JSON.parse(value)
    } catch {
      return value // Keep as string if not valid JSON
    }
  }

  async function handleSubmit(e: Event) {
    e.preventDefault()
    if (!url.trim()) return

    setSaving(true)
    setError(null)

    // Build filter_config if kinds or conditions are set
    const validConditions = conditions.filter(c => c.field.trim())
    const filter_config: FilterConfig | undefined = (filterKinds.length > 0 || validConditions.length > 0)
      ? {
          kinds: filterKinds.length > 0 ? filterKinds : undefined,
          condition_groups: validConditions.length > 0
            ? [validConditions.map(c => ({
                field: c.field.trim(),
                op: c.op,
                value: c.op === 'exists' ? true : parseConditionValue(c.value),
              }))]
            : undefined,
        }
      : undefined

    try {
      const res = await fetch(apiUrl('/api/webhooks'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          name: name.trim() || undefined,
          url: url.trim(),
          event_types: eventTypes,
          filter_config,
          enabled: true,
        }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error?.message || 'Failed to create webhook')
      }

      const webhook = await res.json()
      onCreate(webhook)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create webhook')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: theme.overlay,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: theme.bgCard,
          borderRadius: 12,
          padding: 24,
          width: '90%',
          maxWidth: 480,
          maxHeight: '80vh',
          overflow: 'auto',
        }}
        onClick={e => e.stopPropagation()}
      >
        <h3 style={{ margin: '0 0 20px', color: theme.text }}>Create Outbound Webhook</h3>

        <form onSubmit={handleSubmit as any}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, color: theme.text }}>
              Name (optional)
            </label>
            <input
              type="text"
              value={name}
              onChange={e => setName((e.target as HTMLInputElement).value)}
              placeholder="e.g., Slack Notifications"
              style={{
                width: '100%',
                padding: '10px 12px',
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, color: theme.text }}>
              URL *
            </label>
            <input
              type="url"
              value={url}
              onChange={e => setUrl((e.target as HTMLInputElement).value)}
              placeholder="https://example.com/webhook"
              required
              style={{
                width: '100%',
                padding: '10px 12px',
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ marginBottom: 20 }}>
            <label style={{ display: 'block', marginBottom: 8, fontSize: 14, color: theme.text }}>
              Events
            </label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {availableEvents.map(evt => (
                <label key={evt.id} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={eventTypes.includes(evt.id)}
                    onChange={e => {
                      if ((e.target as HTMLInputElement).checked) {
                        setEventTypes([...eventTypes, evt.id])
                      } else {
                        setEventTypes(eventTypes.filter(t => t !== evt.id))
                      }
                    }}
                    style={{ width: 16, height: 16 }}
                  />
                  <span style={{ fontSize: 14, color: theme.text }}>{evt.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div style={{ marginBottom: 20 }}>
            <label style={{ display: 'block', marginBottom: 8, fontSize: 14, color: theme.text }}>
              Filter by Kind (optional)
            </label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={filterKinds.length === 0}
                  onChange={() => setFilterKinds([])}
                  style={{ width: 16, height: 16 }}
                />
                <span style={{ fontSize: 14, color: theme.text }}>All kinds</span>
              </label>
              {kinds.map(kind => (
                <label key={kind.id} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={filterKinds.includes(kind.name)}
                    onChange={e => {
                      if ((e.target as HTMLInputElement).checked) {
                        setFilterKinds([...filterKinds, kind.name])
                      } else {
                        setFilterKinds(filterKinds.filter(k => k !== kind.name))
                      }
                    }}
                    style={{ width: 16, height: 16 }}
                  />
                  <span style={{ fontSize: 14, color: theme.text }}>{kind.icon} {kind.name}</span>
                </label>
              ))}
            </div>
            <div style={{ marginTop: 6, fontSize: 12, color: theme.textMuted }}>
              {filterKinds.length === 0 ? 'Triggers for all kinds' : `Triggers for: ${filterKinds.join(', ')}`}
            </div>
          </div>

          {/* Attribute Conditions */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <label style={{ fontSize: 14, color: theme.text }}>
                Attribute Filters (optional)
              </label>
              <button
                type="button"
                onClick={addCondition}
                style={{
                  padding: '4px 10px',
                  background: theme.bgHover,
                  color: theme.text,
                  border: `1px solid ${theme.border}`,
                  borderRadius: 4,
                  cursor: 'pointer',
                  fontSize: 12,
                }}
              >
                + Add
              </button>
            </div>
            {conditions.length === 0 ? (
              <div style={{ fontSize: 12, color: theme.textMuted }}>
                No attribute filters. Click "+ Add" to filter by metadata fields.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {conditions.map((condition, index) => (
                  <div key={index} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <input
                      type="text"
                      placeholder="field"
                      value={condition.field}
                      onChange={e => updateCondition(index, { field: (e.target as HTMLInputElement).value })}
                      style={{
                        flex: 1,
                        padding: '6px 10px',
                        border: `1px solid ${theme.border}`,
                        borderRadius: 4,
                        fontSize: 13,
                        background: theme.bgInput,
                        color: theme.text,
                      }}
                    />
                    <select
                      value={condition.op}
                      onChange={e => updateCondition(index, { op: (e.target as HTMLSelectElement).value })}
                      style={{
                        padding: '6px 8px',
                        border: `1px solid ${theme.border}`,
                        borderRadius: 4,
                        fontSize: 13,
                        background: theme.bgInput,
                        color: theme.text,
                        minWidth: 70,
                      }}
                    >
                      {operators.map(op => (
                        <option key={op.id} value={op.id}>{op.label}</option>
                      ))}
                    </select>
                    {condition.op !== 'exists' && (
                      <input
                        type="text"
                        placeholder="value"
                        value={condition.value}
                        onChange={e => updateCondition(index, { value: (e.target as HTMLInputElement).value })}
                        style={{
                          flex: 1,
                          padding: '6px 10px',
                          border: `1px solid ${theme.border}`,
                          borderRadius: 4,
                          fontSize: 13,
                          background: theme.bgInput,
                          color: theme.text,
                        }}
                      />
                    )}
                    <button
                      type="button"
                      onClick={() => removeCondition(index)}
                      style={{
                        padding: '4px 8px',
                        background: 'transparent',
                        color: theme.error,
                        border: 'none',
                        cursor: 'pointer',
                        fontSize: 16,
                      }}
                    >
                      ×
                    </button>
                  </div>
                ))}
                <div style={{ fontSize: 11, color: theme.textMuted, marginTop: 4 }}>
                  Multiple conditions are AND'd together. Use numbers for numeric comparisons.
                </div>
              </div>
            )}
          </div>

          {error && (
            <div style={{ marginBottom: 16, padding: 12, background: 'rgba(239, 68, 68, 0.1)', borderRadius: 6, color: theme.error, fontSize: 13 }}>
              {error}
            </div>
          )}

          <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '10px 20px',
                background: 'transparent',
                color: theme.textMuted,
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                cursor: 'pointer',
                fontSize: 14,
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !url.trim()}
              style={{
                padding: '10px 20px',
                background: theme.accent,
                color: theme.accentText,
                border: 'none',
                borderRadius: 6,
                cursor: saving ? 'wait' : 'pointer',
                fontSize: 14,
                opacity: saving || !url.trim() ? 0.6 : 1,
              }}
            >
              {saving ? 'Creating...' : 'Create Webhook'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// Create Inbound Webhook Modal
function CreateInboundWebhookModal({
  theme,
  kinds,
  onClose,
  onCreate,
}: {
  theme: Theme
  kinds: Kind[]
  onClose: () => void
  onCreate: (webhook: InboundWebhook) => void
}) {
  const [name, setName] = useState('')
  const [sourceSystem, setSourceSystem] = useState('')
  const [thingType, setThingType] = useState(kinds[0]?.name || 'note')
  const [visibility, setVisibility] = useState('private')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: Event) {
    e.preventDefault()
    if (!name.trim() || !sourceSystem.trim()) return

    setSaving(true)
    setError(null)

    try {
      const res = await fetch(apiUrl('/api/webhooks/inbound'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          name: name.trim(),
          source_system: sourceSystem.trim().toLowerCase().replace(/\s+/g, '-'),
          default_thing_type: thingType,
          default_visibility: visibility,
          enabled: true,
        }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error?.message || 'Failed to create webhook')
      }

      const webhook = await res.json()
      onCreate(webhook)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create webhook')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: theme.overlay,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: theme.bgCard,
          borderRadius: 12,
          padding: 24,
          width: '90%',
          maxWidth: 480,
          maxHeight: '80vh',
          overflow: 'auto',
        }}
        onClick={e => e.stopPropagation()}
      >
        <h3 style={{ margin: '0 0 20px', color: theme.text }}>Create Inbound Webhook</h3>

        <form onSubmit={handleSubmit as any}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, color: theme.text }}>
              Name *
            </label>
            <input
              type="text"
              value={name}
              onChange={e => setName((e.target as HTMLInputElement).value)}
              placeholder="e.g., GitHub Importer"
              required
              style={{
                width: '100%',
                padding: '10px 12px',
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, color: theme.text }}>
              Source System *
            </label>
            <input
              type="text"
              value={sourceSystem}
              onChange={e => setSourceSystem((e.target as HTMLInputElement).value)}
              placeholder="e.g., github, notion, zapier"
              required
              style={{
                width: '100%',
                padding: '10px 12px',
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
                boxSizing: 'border-box',
              }}
            />
            <p style={{ margin: '6px 0 0', fontSize: 12, color: theme.textMuted }}>
              Identifier for the source of imported data
            </p>
          </div>

          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, color: theme.text }}>
              Default Thing Type
            </label>
            <select
              value={thingType}
              onChange={e => setThingType((e.target as HTMLSelectElement).value)}
              style={{
                width: '100%',
                padding: '10px 12px',
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
              }}
            >
              {kinds.map(kind => (
                <option key={kind.id} value={kind.name}>
                  {kind.icon} {kind.name}
                </option>
              ))}
            </select>
          </div>

          <div style={{ marginBottom: 20 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, color: theme.text }}>
              Default Visibility
            </label>
            <select
              value={visibility}
              onChange={e => setVisibility((e.target as HTMLSelectElement).value)}
              style={{
                width: '100%',
                padding: '10px 12px',
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
              }}
            >
              <option value="private">Private</option>
              <option value="unlisted">Unlisted</option>
              <option value="public">Public</option>
            </select>
          </div>

          {error && (
            <div style={{ marginBottom: 16, padding: 12, background: 'rgba(239, 68, 68, 0.1)', borderRadius: 6, color: theme.error, fontSize: 13 }}>
              {error}
            </div>
          )}

          <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '10px 20px',
                background: 'transparent',
                color: theme.textMuted,
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                cursor: 'pointer',
                fontSize: 14,
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !name.trim() || !sourceSystem.trim()}
              style={{
                padding: '10px 20px',
                background: theme.accent,
                color: theme.accentText,
                border: 'none',
                borderRadius: 6,
                cursor: saving ? 'wait' : 'pointer',
                fontSize: 14,
                opacity: saving || !name.trim() || !sourceSystem.trim() ? 0.6 : 1,
              }}
            >
              {saving ? 'Creating...' : 'Create Webhook'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
