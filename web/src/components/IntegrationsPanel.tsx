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
    return <div className="text-muted">Loading integrations...</div>
  }

  return (
    <div>
      {/* Outbound Webhooks Section */}
      <div className="mb-8">
        <div className="flex justify-between items-center mb-4">
          <h3 className="m-0 text-base font-semibold" style={{ color: theme.text }}>
            Outbound Webhooks
          </h3>
          <button
            onClick={() => setShowCreateOutbound(true)}
            className="px-3 py-1.5 border rounded-md cursor-pointer text-sm"
            style={{
              background: theme.bgHover,
              color: theme.text,
              borderColor: theme.border,
            }}
          >
            + Add
          </button>
        </div>

        {outboundWebhooks.length === 0 ? (
          <div className="bg-card border border-border rounded-lg p-4 mb-3 text-center text-muted">
            No outbound webhooks configured.
            <br />
            <span className="text-sm">Outbound webhooks send events to external URLs when things happen.</span>
          </div>
        ) : (
          outboundWebhooks.map(webhook => (
            <div key={webhook.id} className="bg-card border border-border rounded-lg p-4 mb-3">
              <div className="flex justify-between items-start gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-semibold" style={{ color: theme.text }}>
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
                  <div className="text-sm text-muted mb-2 overflow-hidden overflow-ellipsis whitespace-nowrap">
                    {webhook.url}
                  </div>
                  <div className="flex gap-1.5 flex-wrap">
                    {webhook.event_types?.map(evt => (
                      <span
                        key={evt}
                        className="text-xs px-2 py-0.5 rounded-xl"
                        style={{
                          background: theme.bgMuted,
                          color: theme.textMuted,
                        }}
                      >
                        {evt}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="flex gap-2 items-center">
                  <button
                    onClick={() => testWebhook(webhook.id)}
                    disabled={testingWebhook === webhook.id}
                    className="px-3 py-1.5 bg-transparent border rounded text-xs"
                    style={{
                      color: theme.accent,
                      borderColor: theme.accent,
                      cursor: testingWebhook === webhook.id ? 'wait' : 'pointer',
                      opacity: testingWebhook === webhook.id ? 0.6 : 1,
                    }}
                  >
                    {testingWebhook === webhook.id ? '...' : 'Test'}
                  </button>
                  <button
                    onClick={() => setExpandedOutbound(expandedOutbound === webhook.id ? null : webhook.id)}
                    className="px-2.5 py-1.5 bg-transparent border-none cursor-pointer text-sm"
                    style={{ color: theme.textMuted }}
                  >
                    {expandedOutbound === webhook.id ? '▲' : '▼'}
                  </button>
                  <button
                    onClick={() => deleteOutboundWebhook(webhook.id)}
                    className="px-2.5 py-1.5 bg-transparent border-none cursor-pointer text-sm"
                    style={{ color: theme.error }}
                  >
                    Delete
                  </button>
                </div>
              </div>

              {/* Test Result */}
              {testResult?.id === webhook.id && (
                <div
                  className="mt-3 p-3 rounded-md flex items-center gap-2"
                  style={{
                    background: testResult.result.success ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                  }}
                >
                  <span className="text-base">{testResult.result.success ? '✓' : '✗'}</span>
                  <span className="text-sm" style={{ color: testResult.result.success ? '#22c55e' : theme.error }}>
                    {testResult.result.success
                      ? `Success • ${testResult.result.status_code} • ${testResult.result.response_time_ms}ms`
                      : testResult.result.error || 'Failed'}
                  </span>
                  <button
                    onClick={() => setTestResult(null)}
                    className="ml-auto bg-transparent border-none cursor-pointer text-xs"
                    style={{ color: theme.textMuted }}
                  >
                    Dismiss
                  </button>
                </div>
              )}

              {/* Expanded Details */}
              {expandedOutbound === webhook.id && (
                <div className="mt-4 pt-4" style={{ borderTop: `1px solid ${theme.border}` }}>
                  <div className="text-sm text-muted mb-2">
                    <strong>URL:</strong> {webhook.url}
                  </div>
                  {webhook.signing_secret && (
                    <div className="text-sm text-muted mb-2">
                      <strong>Signing Secret:</strong>{' '}
                      <code className="px-1.5 py-0.5 rounded" style={{ background: theme.bgMuted }}>
                        {revealedToken === webhook.id ? webhook.signing_secret : '••••••••••••'}
                      </code>
                      <button
                        onClick={() => setRevealedToken(revealedToken === webhook.id ? null : webhook.id)}
                        className="ml-2 bg-transparent border-none cursor-pointer text-xs"
                        style={{ color: theme.accent }}
                      >
                        {revealedToken === webhook.id ? 'Hide' : 'Reveal'}
                      </button>
                    </div>
                  )}
                  {(webhook.filter_config?.kinds?.length || webhook.filter_config?.condition_groups?.length) && (
                    <div className="text-sm text-muted mb-2">
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
                  <div className="text-xs text-muted">
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
        <div className="flex justify-between items-center mb-4">
          <h3 className="m-0 text-base font-semibold" style={{ color: theme.text }}>
            Inbound Webhooks
          </h3>
          <button
            onClick={() => setShowCreateInbound(true)}
            className="px-3 py-1.5 border rounded-md cursor-pointer text-sm"
            style={{
              background: theme.bgHover,
              color: theme.text,
              borderColor: theme.border,
            }}
          >
            + Add
          </button>
        </div>

        {inboundWebhooks.length === 0 ? (
          <div className="bg-card border border-border rounded-lg p-4 mb-3 text-center text-muted">
            No inbound webhooks configured.
            <br />
            <span className="text-sm">Inbound webhooks let external services create things in your account.</span>
          </div>
        ) : (
          inboundWebhooks.map(webhook => (
            <div key={webhook.id} className="bg-card border border-border rounded-lg p-4 mb-3">
              <div className="flex justify-between items-start gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-semibold" style={{ color: theme.text }}>
                      {webhook.name}
                    </span>
                    <span
                      className="text-xs px-2 py-0.5 rounded-xl"
                      style={{
                        background: theme.bgMuted,
                        color: theme.textMuted,
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
                  <div className="text-sm text-muted">
                    Creates: {webhook.default_thing_type} ({webhook.default_visibility})
                  </div>
                </div>
                <div className="flex gap-2 items-center">
                  <button
                    onClick={() => setExpandedInbound(expandedInbound === webhook.id ? null : webhook.id)}
                    className="px-2.5 py-1.5 bg-transparent border-none cursor-pointer text-sm"
                    style={{ color: theme.textMuted }}
                  >
                    {expandedInbound === webhook.id ? '▲' : '▼'}
                  </button>
                  <button
                    onClick={() => deleteInboundWebhook(webhook.id)}
                    className="px-2.5 py-1.5 bg-transparent border-none cursor-pointer text-sm"
                    style={{ color: theme.error }}
                  >
                    Delete
                  </button>
                </div>
              </div>

              {/* Expanded Details */}
              {expandedInbound === webhook.id && (
                <div className="mt-4 pt-4" style={{ borderTop: `1px solid ${theme.border}` }}>
                  <div className="text-sm text-muted mb-3">
                    <strong>Endpoint:</strong>
                    <div className="mt-1 flex items-center gap-2">
                      <code
                        className="px-2.5 py-1.5 rounded text-xs flex-1 break-all"
                        style={{ background: theme.bgMuted }}
                      >
                        POST {window.location.origin}/api/webhooks/receive/{webhook.id}?token=...
                      </code>
                      <button
                        onClick={() => {
                          const url = `${window.location.origin}/api/webhooks/receive/${webhook.id}?token=${webhook.secret_token || webhook.token_prefix + '...'}`
                          copyToClipboard(url, 'url-' + webhook.id)
                        }}
                        className="px-2.5 py-1.5 border rounded cursor-pointer text-xs"
                        style={{
                          background: theme.bgHover,
                          color: copiedId === 'url-' + webhook.id ? '#22c55e' : theme.text,
                          borderColor: theme.border,
                        }}
                      >
                        {copiedId === 'url-' + webhook.id ? 'Copied!' : 'Copy'}
                      </button>
                    </div>
                  </div>
                  <div className="text-sm text-muted mb-2">
                    <strong>Token:</strong>{' '}
                    <code className="px-1.5 py-0.5 rounded" style={{ background: theme.bgMuted }}>
                      {revealedToken === 'inbound-' + webhook.id
                        ? (webhook.secret_token || webhook.token_prefix + '...')
                        : webhook.token_prefix + '••••••••'}
                    </code>
                    <button
                      onClick={() => setRevealedToken(revealedToken === 'inbound-' + webhook.id ? null : 'inbound-' + webhook.id)}
                      className="ml-2 bg-transparent border-none cursor-pointer text-xs"
                      style={{ color: theme.accent }}
                    >
                      {revealedToken === 'inbound-' + webhook.id ? 'Hide' : 'Reveal'}
                    </button>
                  </div>
                  <div className="text-sm text-muted mb-3">
                    <strong>Example curl:</strong>
                    <pre className="mt-1 p-3 rounded text-xs overflow-auto whitespace-pre-wrap break-all" style={{ background: theme.bgMuted }}>
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
                      className="mt-2 px-3 py-1.5 border rounded cursor-pointer text-xs"
                      style={{
                        background: theme.bgHover,
                        color: copiedId === 'curl-' + webhook.id ? '#22c55e' : theme.text,
                        borderColor: theme.border,
                      }}
                    >
                      {copiedId === 'curl-' + webhook.id ? 'Copied!' : 'Copy curl'}
                    </button>
                  </div>
                  <div className="text-sm text-muted mb-2">
                    <strong>Payload fields:</strong>
                    <ul className="m-0 mt-2 pl-5 text-xs">
                      <li><code>content</code> - The text content of the Thing (required)</li>
                      <li><code>metadata</code> - Optional JSON object with additional attributes</li>
                      <li><code>external_id</code> - Optional unique ID for deduplication</li>
                    </ul>
                  </div>
                  <div className="text-xs text-muted">
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
      className="fixed inset-0 flex items-center justify-center z-[1000]"
      style={{ background: theme.overlay }}
      onClick={onClose}
    >
      <div
        className="rounded-xl p-6 w-[90%] max-w-[480px] max-h-[80vh] overflow-auto"
        style={{ background: theme.bgCard }}
        onClick={e => e.stopPropagation()}
      >
        <h3 className="m-0 mb-5" style={{ color: theme.text }}>Create Outbound Webhook</h3>

        <form onSubmit={handleSubmit as any}>
          <div className="mb-4">
            <label className="block mb-1.5 text-sm" style={{ color: theme.text }}>
              Name (optional)
            </label>
            <input
              type="text"
              value={name}
              onChange={e => setName((e.target as HTMLInputElement).value)}
              placeholder="e.g., Slack Notifications"
              className="w-full px-3 py-2.5 border rounded-md text-sm box-border"
              style={{
                borderColor: theme.border,
                background: theme.bgInput,
                color: theme.text,
              }}
            />
          </div>

          <div className="mb-4">
            <label className="block mb-1.5 text-sm" style={{ color: theme.text }}>
              URL *
            </label>
            <input
              type="url"
              value={url}
              onChange={e => setUrl((e.target as HTMLInputElement).value)}
              placeholder="https://example.com/webhook"
              required
              className="w-full px-3 py-2.5 border rounded-md text-sm box-border"
              style={{
                borderColor: theme.border,
                background: theme.bgInput,
                color: theme.text,
              }}
            />
          </div>

          <div className="mb-5">
            <label className="block mb-2 text-sm" style={{ color: theme.text }}>
              Events
            </label>
            <div className="flex flex-col gap-2">
              {availableEvents.map(evt => (
                <label key={evt.id} className="flex items-center gap-2 cursor-pointer">
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
                    className="w-4 h-4"
                  />
                  <span className="text-sm" style={{ color: theme.text }}>{evt.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="mb-5">
            <label className="block mb-2 text-sm" style={{ color: theme.text }}>
              Filter by Kind (optional)
            </label>
            <div className="flex flex-col gap-2">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={filterKinds.length === 0}
                  onChange={() => setFilterKinds([])}
                  className="w-4 h-4"
                />
                <span className="text-sm" style={{ color: theme.text }}>All kinds</span>
              </label>
              {kinds.map(kind => (
                <label key={kind.id} className="flex items-center gap-2 cursor-pointer">
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
                    className="w-4 h-4"
                  />
                  <span className="text-sm" style={{ color: theme.text }}>{kind.icon} {kind.name}</span>
                </label>
              ))}
            </div>
            <div className="mt-1.5 text-xs text-muted">
              {filterKinds.length === 0 ? 'Triggers for all kinds' : `Triggers for: ${filterKinds.join(', ')}`}
            </div>
          </div>

          {/* Attribute Conditions */}
          <div className="mb-5">
            <div className="flex justify-between items-center mb-2">
              <label className="text-sm" style={{ color: theme.text }}>
                Attribute Filters (optional)
              </label>
              <button
                type="button"
                onClick={addCondition}
                className="px-2.5 py-1 border rounded cursor-pointer text-xs"
                style={{
                  background: theme.bgHover,
                  color: theme.text,
                  borderColor: theme.border,
                }}
              >
                + Add
              </button>
            </div>
            {conditions.length === 0 ? (
              <div className="text-xs text-muted">
                No attribute filters. Click "+ Add" to filter by metadata fields.
              </div>
            ) : (
              <div className="flex flex-col gap-2">
                {conditions.map((condition, index) => (
                  <div key={index} className="flex gap-2 items-center">
                    <input
                      type="text"
                      placeholder="field"
                      value={condition.field}
                      onChange={e => updateCondition(index, { field: (e.target as HTMLInputElement).value })}
                      className="flex-1 px-2.5 py-1.5 border rounded text-sm"
                      style={{
                        borderColor: theme.border,
                        background: theme.bgInput,
                        color: theme.text,
                      }}
                    />
                    <select
                      value={condition.op}
                      onChange={e => updateCondition(index, { op: (e.target as HTMLSelectElement).value })}
                      className="px-2 py-1.5 border rounded text-sm min-w-[70px]"
                      style={{
                        borderColor: theme.border,
                        background: theme.bgInput,
                        color: theme.text,
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
                        className="flex-1 px-2.5 py-1.5 border rounded text-sm"
                        style={{
                          borderColor: theme.border,
                          background: theme.bgInput,
                          color: theme.text,
                        }}
                      />
                    )}
                    <button
                      type="button"
                      onClick={() => removeCondition(index)}
                      className="px-2 py-1 bg-transparent border-none cursor-pointer text-base"
                      style={{ color: theme.error }}
                    >
                      ×
                    </button>
                  </div>
                ))}
                <div className="text-xs text-muted mt-1">
                  Multiple conditions are AND'd together. Use numbers for numeric comparisons.
                </div>
              </div>
            )}
          </div>

          {error && (
            <div className="mb-4 p-3 rounded-md text-sm" style={{ background: 'rgba(239, 68, 68, 0.1)', color: theme.error }}>
              {error}
            </div>
          )}

          <div className="flex gap-3 justify-end">
            <button
              type="button"
              onClick={onClose}
              className="px-5 py-2.5 bg-transparent border rounded-md cursor-pointer text-sm"
              style={{
                color: theme.textMuted,
                borderColor: theme.border,
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !url.trim()}
              className="px-5 py-2.5 border-none rounded-md text-sm"
              style={{
                background: theme.accent,
                color: theme.accentText,
                cursor: saving ? 'wait' : 'pointer',
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
      className="fixed inset-0 flex items-center justify-center z-[1000]"
      style={{ background: theme.overlay }}
      onClick={onClose}
    >
      <div
        className="rounded-xl p-6 w-[90%] max-w-[480px] max-h-[80vh] overflow-auto"
        style={{ background: theme.bgCard }}
        onClick={e => e.stopPropagation()}
      >
        <h3 className="m-0 mb-5" style={{ color: theme.text }}>Create Inbound Webhook</h3>

        <form onSubmit={handleSubmit as any}>
          <div className="mb-4">
            <label className="block mb-1.5 text-sm" style={{ color: theme.text }}>
              Name *
            </label>
            <input
              type="text"
              value={name}
              onChange={e => setName((e.target as HTMLInputElement).value)}
              placeholder="e.g., GitHub Importer"
              required
              className="w-full px-3 py-2.5 border rounded-md text-sm box-border"
              style={{
                borderColor: theme.border,
                background: theme.bgInput,
                color: theme.text,
              }}
            />
          </div>

          <div className="mb-4">
            <label className="block mb-1.5 text-sm" style={{ color: theme.text }}>
              Source System *
            </label>
            <input
              type="text"
              value={sourceSystem}
              onChange={e => setSourceSystem((e.target as HTMLInputElement).value)}
              placeholder="e.g., github, notion, zapier"
              required
              className="w-full px-3 py-2.5 border rounded-md text-sm box-border"
              style={{
                borderColor: theme.border,
                background: theme.bgInput,
                color: theme.text,
              }}
            />
            <p className="m-0 mt-1.5 text-xs text-muted">
              Identifier for the source of imported data
            </p>
          </div>

          <div className="mb-4">
            <label className="block mb-1.5 text-sm" style={{ color: theme.text }}>
              Default Thing Type
            </label>
            <select
              value={thingType}
              onChange={e => setThingType((e.target as HTMLSelectElement).value)}
              className="w-full px-3 py-2.5 border rounded-md text-sm"
              style={{
                borderColor: theme.border,
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

          <div className="mb-5">
            <label className="block mb-1.5 text-sm" style={{ color: theme.text }}>
              Default Visibility
            </label>
            <select
              value={visibility}
              onChange={e => setVisibility((e.target as HTMLSelectElement).value)}
              className="w-full px-3 py-2.5 border rounded-md text-sm"
              style={{
                borderColor: theme.border,
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
            <div className="mb-4 p-3 rounded-md text-sm" style={{ background: 'rgba(239, 68, 68, 0.1)', color: theme.error }}>
              {error}
            </div>
          )}

          <div className="flex gap-3 justify-end">
            <button
              type="button"
              onClick={onClose}
              className="px-5 py-2.5 bg-transparent border rounded-md cursor-pointer text-sm"
              style={{
                color: theme.textMuted,
                borderColor: theme.border,
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !name.trim() || !sourceSystem.trim()}
              className="px-5 py-2.5 border-none rounded-md text-sm"
              style={{
                background: theme.accent,
                color: theme.accentText,
                cursor: saving ? 'wait' : 'pointer',
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
