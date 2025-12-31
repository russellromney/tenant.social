import { useState, useEffect } from 'preact/hooks'
import { Theme } from '../theme'
import { Kind } from '../types'
import { apiUrl } from '../api'
import { EmojiPicker } from './EmojiPicker'

// API Key interface
interface APIKey {
  id: string
  name: string
  key_prefix: string
  scopes: string[]
  last_used_at: string | null
  created_at: string
}

// Kinds Management Panel
export function KindsPanel({
  kinds,
  onCreateKind,
  onDeleteKind,
  setEditingKind,
  usedEmojis,
  theme,
  defaultKindId,
  onSetDefaultKind,
}: {
  kinds: Kind[]
  onCreateKind: (k: Partial<Kind>) => Promise<Kind | undefined>
  onDeleteKind: (id: string) => void
  setEditingKind: (k: Kind | null) => void
  usedEmojis: string[]
  theme: Theme
  defaultKindId: string | null
  onSetDefaultKind: (id: string | null) => void
}) {
  const [newName, setNewName] = useState('')
  const [newIcon, setNewIcon] = useState('')

  async function handleCreate(e: Event) {
    e.preventDefault()
    if (!newName.trim() || !newIcon) return
    await onCreateKind({ name: newName.toLowerCase(), icon: newIcon, attributes: [] })
    setNewName('')
    setNewIcon('')
  }

  return (
    <div>
      <h2 style={{ fontSize: 20, margin: '0 0 16px', color: theme.text }}>Kinds</h2>

      {/* Default Kind Selector */}
      <div style={{
        padding: 16,
        background: theme.bgCard,
        borderRadius: 12,
        border: `1px solid ${theme.border}`,
        marginBottom: 24,
      }}>
        <label style={{ display: 'block', fontSize: 14, color: theme.textMuted, marginBottom: 8 }}>
          Default Kind
        </label>
        <select
          value={defaultKindId || ''}
          onChange={e => onSetDefaultKind(e.currentTarget.value || null)}
          style={{
            width: '100%',
            padding: '10px 14px',
            border: `1px solid ${theme.borderInput}`,
            borderRadius: 6,
            background: theme.bgInput,
            color: theme.text,
            fontSize: 14,
          }}
        >
          <option value="">First in list</option>
          {kinds.map(k => (
            <option key={k.id} value={k.id}>{k.icon} {k.name}</option>
          ))}
        </select>
        <p style={{ fontSize: 12, color: theme.textMuted, marginTop: 8, marginBottom: 0 }}>
          This Kind will be pre-selected when creating new Things.
        </p>
      </div>

      {/* Create new kind */}
      <form onSubmit={handleCreate} style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
          <div>
            <label style={{ fontSize: 12, color: theme.textMuted, display: 'block', marginBottom: 4 }}>Icon</label>
            <EmojiPicker value={newIcon} onChange={setNewIcon} usedEmojis={usedEmojis} theme={theme} />
          </div>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 12, color: theme.textMuted, display: 'block', marginBottom: 4 }}>Name</label>
            <input
              type="text"
              value={newName}
              onInput={e => setNewName((e.target as HTMLInputElement).value)}
              placeholder="New kind name..."
              style={{ width: '100%', padding: '10px 14px', border: `1px solid ${theme.borderInput}`, borderRadius: 6, boxSizing: 'border-box', background: theme.bgInput, color: theme.text }}
            />
          </div>
          <button
            type="submit"
            disabled={!newName.trim() || !newIcon}
            style={{
              padding: '10px 20px',
              background: newName.trim() && newIcon ? theme.accent : theme.textDisabled,
              color: newName.trim() && newIcon ? theme.accentText : theme.textSubtle,
              border: 'none',
              borderRadius: 6,
              cursor: newName.trim() && newIcon ? 'pointer' : 'not-allowed',
              height: 42,
            }}
          >
            Add
          </button>
        </div>
      </form>

      {/* List of kinds */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {kinds.map(kind => (
          <div
            key={kind.id}
            style={{
              padding: 16,
              background: theme.bgCard,
              borderRadius: 8,
              border: defaultKindId === kind.id ? `2px solid ${theme.accent}` : `1px solid ${theme.border}`,
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  width: 36,
                  height: 36,
                  background: theme.bgMuted,
                  borderRadius: 8,
                  fontSize: 18,
                }}
              >
                {kind.icon || '•'}
              </span>
              <div>
                <div style={{ fontWeight: 600, color: theme.text }}>
                  {kind.name}
                  {defaultKindId === kind.id && (
                    <span style={{ marginLeft: 8, fontSize: 11, color: theme.accent, fontWeight: 500 }}>DEFAULT</span>
                  )}
                </div>
                <div style={{ fontSize: 12, color: theme.textSubtle }}>
                  {kind.attributes?.length || 0} attributes
                  {kind.commentable && ' • replies enabled'}
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                onClick={() => setEditingKind(kind)}
                style={{
                  padding: '6px 12px',
                  background: theme.bgHover,
                  color: theme.text,
                  border: 'none',
                  borderRadius: 4,
                  cursor: 'pointer',
                }}
              >
                Edit
              </button>
              <button
                onClick={() => onDeleteKind(kind.id)}
                style={{
                  padding: '6px 12px',
                  background: theme.errorBg,
                  color: theme.errorText,
                  border: 'none',
                  borderRadius: 4,
                  cursor: 'pointer',
                }}
              >
                Delete
              </button>
            </div>
          </div>
        ))}
        {kinds.length === 0 && (
          <p style={{ color: theme.textMuted, textAlign: 'center', padding: 20 }}>
            No kinds yet. Create one above!
          </p>
        )}
      </div>
    </div>
  )
}

// Data Export/Import Panel
export function DataExportPanel({
  theme,
  onImportComplete,
}: {
  theme: Theme
  onImportComplete: () => void
}) {
  const [importing, setImporting] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null)

  async function handleExport() {
    setExporting(true)
    setMessage(null)
    try {
      const res = await fetch(apiUrl('/api/export'), { credentials: 'include' })
      if (!res.ok) throw new Error('Export failed')

      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `tenant-export-${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      setMessage({ type: 'success', text: 'Export downloaded successfully!' })
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to export data' })
    } finally {
      setExporting(false)
    }
  }

  async function handleImport(e: Event) {
    const input = e.target as HTMLInputElement
    const file = input.files?.[0]
    if (!file) return

    setImporting(true)
    setMessage(null)
    try {
      const text = await file.text()
      const res = await fetch(apiUrl('/api/import'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: text,
      })

      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.error || 'Import failed')
      }

      const result = await res.json()
      setMessage({
        type: 'success',
        text: `Imported ${result.kindsCreated} kinds and ${result.thingsCreated} things (${result.kindsSkipped + result.thingsSkipped} skipped)`
      })
      onImportComplete()
    } catch (err) {
      setMessage({ type: 'error', text: err instanceof Error ? err.message : 'Failed to import data' })
    } finally {
      setImporting(false)
      input.value = '' // Reset file input
    }
  }

  return (
    <div>
      <h2 style={{ fontSize: 20, margin: '0 0 16px', color: theme.text }}>Data</h2>
      <p style={{ color: theme.textSecondary, marginBottom: 24, lineHeight: 1.6 }}>
        Export and import your things and kinds.
      </p>

      {/* Export Section */}
      <div style={{
        padding: 20,
        background: theme.bgCard,
        borderRadius: 12,
        border: `1px solid ${theme.border}`,
        marginBottom: 16,
      }}>
        <h3 style={{ fontSize: 16, margin: '0 0 8px', color: theme.text }}>Export</h3>
        <p style={{ fontSize: 14, color: theme.textMuted, margin: '0 0 16px' }}>
          Download all your things and kinds as a JSON file.
        </p>
        <button
          onClick={handleExport}
          disabled={exporting}
          style={{
            padding: '10px 20px',
            background: exporting ? theme.textDisabled : theme.accent,
            color: exporting ? theme.textSubtle : theme.accentText,
            border: 'none',
            borderRadius: 6,
            cursor: exporting ? 'not-allowed' : 'pointer',
            fontSize: 14,
          }}
        >
          {exporting ? 'Exporting...' : 'Download Export'}
        </button>
      </div>

      {/* Import Section */}
      <div style={{
        padding: 20,
        background: theme.bgCard,
        borderRadius: 12,
        border: `1px solid ${theme.border}`,
        marginBottom: 16,
      }}>
        <h3 style={{ fontSize: 16, margin: '0 0 8px', color: theme.text }}>Import</h3>
        <p style={{ fontSize: 14, color: theme.textMuted, margin: '0 0 16px' }}>
          Import things and kinds from a tenant export file. Duplicates will be skipped.
        </p>
        <label style={{
          display: 'inline-block',
          padding: '10px 20px',
          background: importing ? theme.textDisabled : theme.bgHover,
          color: importing ? theme.textSubtle : theme.text,
          border: `1px solid ${theme.border}`,
          borderRadius: 6,
          cursor: importing ? 'not-allowed' : 'pointer',
          fontSize: 14,
        }}>
          {importing ? 'Importing...' : 'Choose File'}
          <input
            type="file"
            accept=".json"
            onChange={handleImport}
            disabled={importing}
            style={{ display: 'none' }}
          />
        </label>
      </div>

      {/* Status Message */}
      {message && (
        <div style={{
          padding: 12,
          background: message.type === 'success' ? theme.success : theme.errorBg,
          color: message.type === 'success' ? theme.successText : theme.errorText,
          borderRadius: 8,
          fontSize: 14,
        }}>
          {message.text}
        </div>
      )}
    </div>
  )
}

// API Keys Panel
export function APIKeysPanel({ theme }: { theme: Theme }) {
  const [apiKeys, setApiKeys] = useState<APIKey[]>([])
  const [availableScopes, setAvailableScopes] = useState<string[]>([])
  const [showCreateKey, setShowCreateKey] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyScopes, setNewKeyScopes] = useState<string[]>([])
  const [isAdminKey, setIsAdminKey] = useState(true)
  const [createdKey, setCreatedKey] = useState<string | null>(null)
  const [keyCopied, setKeyCopied] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null)

  useEffect(() => {
    fetchAPIKeys()
  }, [])

  async function fetchAPIKeys() {
    try {
      const res = await fetch(apiUrl('/api/keys'), { credentials: 'include' })
      if (res.ok) {
        const data = await res.json()
        setApiKeys(data.keys || [])
        setAvailableScopes(data.availableScopes || [])
      }
    } catch (err) {
      console.error('Failed to fetch API keys:', err)
    }
  }

  async function createAPIKey(e: Event) {
    e.preventDefault()
    if (!newKeyName.trim()) return

    try {
      const res = await fetch(apiUrl('/api/keys'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          name: newKeyName,
          scopes: isAdminKey ? [] : newKeyScopes,
        }),
      })

      if (!res.ok) throw new Error('Failed to create key')

      const data = await res.json()
      setCreatedKey(data.key)
      setNewKeyName('')
      setNewKeyScopes([])
      setIsAdminKey(true)
      setShowCreateKey(false)
      fetchAPIKeys()
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to create API key' })
    }
  }

  async function deleteAPIKey(id: string) {
    if (!confirm('Delete this API key? This cannot be undone.')) return

    try {
      await fetch(apiUrl(`/api/keys/${id}`), {
        method: 'DELETE',
        credentials: 'include',
      })
      fetchAPIKeys()
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to delete API key' })
    }
  }

  function copyKey() {
    if (createdKey) {
      navigator.clipboard.writeText(createdKey)
      setKeyCopied(true)
      setTimeout(() => setKeyCopied(false), 2000)
    }
  }

  return (
    <div>
      <h2 style={{ fontSize: 20, margin: '0 0 16px', color: theme.text }}>API Keys</h2>
      <p style={{ color: theme.textSecondary, marginBottom: 24, lineHeight: 1.6 }}>
        Create API keys for programmatic access. Keys can have full admin access or be scoped to specific permissions.
      </p>

      {/* Status Message */}
      {message && (
        <div style={{
          padding: 12,
          background: message.type === 'success' ? theme.success : theme.errorBg,
          color: message.type === 'success' ? theme.successText : theme.errorText,
          borderRadius: 8,
          fontSize: 14,
          marginBottom: 16,
        }}>
          {message.text}
        </div>
      )}

      {/* Created Key Display */}
      {createdKey && (
        <div style={{
          padding: 16,
          background: theme.success,
          borderRadius: 12,
          marginBottom: 16,
        }}>
          <div style={{ fontWeight: 600, marginBottom: 8, color: theme.successText }}>
            API Key Created - Save this now!
          </div>
          <div style={{
            display: 'flex',
            gap: 8,
            alignItems: 'center',
            background: theme.bgCard,
            padding: 12,
            borderRadius: 6,
            fontFamily: 'monospace',
            fontSize: 14,
            wordBreak: 'break-all',
          }}>
            <code style={{ flex: 1, color: theme.text }}>{createdKey}</code>
            <button
              onClick={copyKey}
              style={{
                padding: '6px 12px',
                background: theme.accent,
                color: theme.accentText,
                border: 'none',
                borderRadius: 4,
                cursor: 'pointer',
                fontSize: 12,
              }}
            >
              {keyCopied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <button
            onClick={() => setCreatedKey(null)}
            style={{
              marginTop: 12,
              padding: '8px 16px',
              background: 'transparent',
              color: theme.successText,
              border: `1px solid ${theme.successText}`,
              borderRadius: 6,
              cursor: 'pointer',
              fontSize: 13,
            }}
          >
            I've saved the key
          </button>
        </div>
      )}

      {/* Create New Key */}
      <div style={{
        padding: 20,
        background: theme.bgCard,
        borderRadius: 12,
        border: `1px solid ${theme.border}`,
        marginBottom: 16,
      }}>
        {!showCreateKey ? (
          <button
            onClick={() => setShowCreateKey(true)}
            style={{
              padding: '10px 20px',
              background: theme.accent,
              color: theme.accentText,
              border: 'none',
              borderRadius: 6,
              cursor: 'pointer',
              fontSize: 14,
            }}
          >
            + Create New API Key
          </button>
        ) : (
          <form onSubmit={createAPIKey}>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: 14, color: theme.textMuted, marginBottom: 6 }}>
                Key Name
              </label>
              <input
                type="text"
                value={newKeyName}
                onInput={e => setNewKeyName((e.target as HTMLInputElement).value)}
                placeholder="e.g., Chrome Extension, Mobile App..."
                style={{
                  width: '100%',
                  padding: '10px 14px',
                  border: `1px solid ${theme.borderInput}`,
                  borderRadius: 6,
                  background: theme.bgInput,
                  color: theme.text,
                  fontSize: 14,
                  boxSizing: 'border-box',
                }}
              />
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={isAdminKey}
                  onChange={e => setIsAdminKey((e.target as HTMLInputElement).checked)}
                />
                <span style={{ color: theme.text }}>Admin key (all permissions)</span>
              </label>
            </div>

            {!isAdminKey && (
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', fontSize: 14, color: theme.textMuted, marginBottom: 8 }}>
                  Scopes
                </label>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {availableScopes.map(scope => (
                    <label
                      key={scope}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 6,
                        padding: '6px 10px',
                        background: newKeyScopes.includes(scope) ? theme.accent : theme.bgHover,
                        color: newKeyScopes.includes(scope) ? theme.accentText : theme.text,
                        borderRadius: 6,
                        cursor: 'pointer',
                        fontSize: 13,
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={newKeyScopes.includes(scope)}
                        onChange={e => {
                          if ((e.target as HTMLInputElement).checked) {
                            setNewKeyScopes([...newKeyScopes, scope])
                          } else {
                            setNewKeyScopes(newKeyScopes.filter(s => s !== scope))
                          }
                        }}
                        style={{ display: 'none' }}
                      />
                      {scope}
                    </label>
                  ))}
                </div>
              </div>
            )}

            <div style={{ display: 'flex', gap: 8 }}>
              <button
                type="submit"
                disabled={!newKeyName.trim() || (!isAdminKey && newKeyScopes.length === 0)}
                style={{
                  padding: '10px 20px',
                  background: newKeyName.trim() && (isAdminKey || newKeyScopes.length > 0)
                    ? theme.accent
                    : theme.textDisabled,
                  color: newKeyName.trim() && (isAdminKey || newKeyScopes.length > 0)
                    ? theme.accentText
                    : theme.textSubtle,
                  border: 'none',
                  borderRadius: 6,
                  cursor: newKeyName.trim() && (isAdminKey || newKeyScopes.length > 0)
                    ? 'pointer'
                    : 'not-allowed',
                  fontSize: 14,
                }}
              >
                Create Key
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowCreateKey(false)
                  setNewKeyName('')
                  setNewKeyScopes([])
                  setIsAdminKey(true)
                }}
                style={{
                  padding: '10px 20px',
                  background: theme.bgHover,
                  color: theme.textMuted,
                  border: 'none',
                  borderRadius: 6,
                  cursor: 'pointer',
                  fontSize: 14,
                }}
              >
                Cancel
              </button>
            </div>
          </form>
        )}
      </div>

      {/* Existing Keys */}
      {apiKeys.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {apiKeys.map(key => (
            <div
              key={key.id}
              style={{
                padding: 16,
                background: theme.bgCard,
                borderRadius: 8,
                border: `1px solid ${theme.border}`,
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: 12,
              }}
            >
              <div>
                <div style={{ fontWeight: 600, color: theme.text, marginBottom: 4 }}>
                  {key.name}
                </div>
                <div style={{ fontSize: 12, color: theme.textMuted }}>
                  <code style={{ background: theme.bgMuted, padding: '2px 6px', borderRadius: 4 }}>
                    {key.key_prefix}...
                  </code>
                  {' • '}
                  {key.scopes.length === availableScopes.length ? 'Admin' : `${key.scopes.length} scopes`}
                  {key.last_used_at && (
                    <>
                      {' • Last used '}
                      {new Date(key.last_used_at).toLocaleDateString()}
                    </>
                  )}
                </div>
              </div>
              <button
                onClick={() => deleteAPIKey(key.id)}
                style={{
                  padding: '6px 12px',
                  background: theme.errorBg,
                  color: theme.errorText,
                  border: 'none',
                  borderRadius: 4,
                  cursor: 'pointer',
                  fontSize: 13,
                }}
              >
                Delete
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
