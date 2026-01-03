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
      <h2 className="text-xl mb-4" style={{ color: theme.text }}>Kinds</h2>

      {/* Default Kind Selector */}
      <div className="p-4 bg-card rounded-xl border border-border mb-6">
        <label className="block text-sm text-muted mb-2">
          Default Kind
        </label>
        <select
          value={defaultKindId || ''}
          onChange={e => onSetDefaultKind(e.currentTarget.value || null)}
          className="w-full px-3.5 py-2.5 border rounded-md text-sm"
          style={{
            borderColor: theme.borderInput,
            background: theme.bgInput,
            color: theme.text,
          }}
        >
          <option value="">First in list</option>
          {kinds.map(k => (
            <option key={k.id} value={k.id}>{k.icon} {k.name}</option>
          ))}
        </select>
        <p className="text-xs text-muted mt-2 mb-0">
          This Kind will be pre-selected when creating new Things.
        </p>
      </div>

      {/* Create new kind */}
      <form onSubmit={handleCreate} className="mb-6">
        <div className="flex gap-2 items-end">
          <div>
            <label className="text-xs text-muted block mb-1">Icon</label>
            <EmojiPicker value={newIcon} onChange={setNewIcon} usedEmojis={usedEmojis} theme={theme} />
          </div>
          <div className="flex-1">
            <label className="text-xs text-muted block mb-1">Name</label>
            <input
              type="text"
              value={newName}
              onInput={e => setNewName((e.target as HTMLInputElement).value)}
              placeholder="New kind name..."
              className="w-full px-3.5 py-2.5 border rounded-md box-border"
              style={{ borderColor: theme.borderInput, background: theme.bgInput, color: theme.text }}
            />
          </div>
          <button
            type="submit"
            disabled={!newName.trim() || !newIcon}
            className="px-5 py-2.5 border-none rounded-md h-[42px]"
            style={{
              background: newName.trim() && newIcon ? theme.accent : theme.textDisabled,
              color: newName.trim() && newIcon ? theme.accentText : theme.textSubtle,
              cursor: newName.trim() && newIcon ? 'pointer' : 'not-allowed',
            }}
          >
            Add
          </button>
        </div>
      </form>

      {/* List of kinds */}
      <div className="flex flex-col gap-2">
        {kinds.map(kind => (
          <div
            key={kind.id}
            className="p-4 bg-card rounded-lg flex justify-between items-center"
            style={{
              border: defaultKindId === kind.id ? `2px solid ${theme.accent}` : `1px solid ${theme.border}`,
            }}
          >
            <div className="flex items-center gap-3">
              <span
                className="inline-flex items-center justify-center w-9 h-9 rounded-lg text-lg"
                style={{ background: theme.bgMuted }}
              >
                {kind.icon || '•'}
              </span>
              <div>
                <div className="font-semibold" style={{ color: theme.text }}>
                  {kind.name}
                  {defaultKindId === kind.id && (
                    <span className="ml-2 text-[11px] font-medium" style={{ color: theme.accent }}>DEFAULT</span>
                  )}
                </div>
                <div className="text-xs" style={{ color: theme.textSubtle }}>
                  {kind.attributes?.length || 0} attributes
                  {kind.commentable && ' • replies enabled'}
                </div>
              </div>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setEditingKind(kind)}
                className="px-3 py-1.5 border-none rounded cursor-pointer"
                style={{
                  background: theme.bgHover,
                  color: theme.text,
                }}
              >
                Edit
              </button>
              <button
                onClick={() => onDeleteKind(kind.id)}
                className="px-3 py-1.5 border-none rounded cursor-pointer"
                style={{
                  background: theme.errorBg,
                  color: theme.errorText,
                }}
              >
                Delete
              </button>
            </div>
          </div>
        ))}
        {kinds.length === 0 && (
          <p className="text-center p-5" style={{ color: theme.textMuted }}>
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
      <h2 className="text-xl mb-4" style={{ color: theme.text }}>Data</h2>
      <p className="mb-6 leading-relaxed" style={{ color: theme.textSecondary }}>
        Export and import your things and kinds.
      </p>

      {/* Export Section */}
      <div className="p-5 bg-card rounded-xl border border-border mb-4">
        <h3 className="text-base m-0 mb-2" style={{ color: theme.text }}>Export</h3>
        <p className="text-sm text-muted m-0 mb-4">
          Download all your things and kinds as a JSON file.
        </p>
        <button
          onClick={handleExport}
          disabled={exporting}
          className="px-5 py-2.5 border-none rounded-md text-sm"
          style={{
            background: exporting ? theme.textDisabled : theme.accent,
            color: exporting ? theme.textSubtle : theme.accentText,
            cursor: exporting ? 'not-allowed' : 'pointer',
          }}
        >
          {exporting ? 'Exporting...' : 'Download Export'}
        </button>
      </div>

      {/* Import Section */}
      <div className="p-5 bg-card rounded-xl border border-border mb-4">
        <h3 className="text-base m-0 mb-2" style={{ color: theme.text }}>Import</h3>
        <p className="text-sm text-muted m-0 mb-4">
          Import things and kinds from a tenant export file. Duplicates will be skipped.
        </p>
        <label className="inline-block px-5 py-2.5 border border-border rounded-md text-sm"
          style={{
            background: importing ? theme.textDisabled : theme.bgHover,
            color: importing ? theme.textSubtle : theme.text,
            cursor: importing ? 'not-allowed' : 'pointer',
          }}>
          {importing ? 'Importing...' : 'Choose File'}
          <input
            type="file"
            accept=".json"
            onChange={handleImport}
            disabled={importing}
            className="hidden"
          />
        </label>
      </div>

      {/* Status Message */}
      {message && (
        <div className="p-3 rounded-lg text-sm"
          style={{
            background: message.type === 'success' ? theme.success : theme.errorBg,
            color: message.type === 'success' ? theme.successText : theme.errorText,
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
      <h2 className="text-xl mb-4" style={{ color: theme.text }}>API Keys</h2>
      <p className="mb-6 leading-relaxed" style={{ color: theme.textSecondary }}>
        Create API keys for programmatic access. Keys can have full admin access or be scoped to specific permissions.
      </p>

      {/* Status Message */}
      {message && (
        <div className="p-3 rounded-lg text-sm mb-4"
          style={{
            background: message.type === 'success' ? theme.success : theme.errorBg,
            color: message.type === 'success' ? theme.successText : theme.errorText,
          }}>
          {message.text}
        </div>
      )}

      {/* Created Key Display */}
      {createdKey && (
        <div className="p-4 rounded-xl mb-4" style={{ background: theme.success }}>
          <div className="font-semibold mb-2" style={{ color: theme.successText }}>
            API Key Created - Save this now!
          </div>
          <div className="flex gap-2 items-center bg-card p-3 rounded-md font-mono text-sm break-all">
            <code className="flex-1" style={{ color: theme.text }}>{createdKey}</code>
            <button
              onClick={copyKey}
              className="px-3 py-1.5 border-none rounded cursor-pointer text-xs"
              style={{
                background: theme.accent,
                color: theme.accentText,
              }}
            >
              {keyCopied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <button
            onClick={() => setCreatedKey(null)}
            className="mt-3 px-4 py-2 bg-transparent rounded-md cursor-pointer text-[13px]"
            style={{
              color: theme.successText,
              border: `1px solid ${theme.successText}`,
            }}
          >
            I've saved the key
          </button>
        </div>
      )}

      {/* Create New Key */}
      <div className="p-5 bg-card rounded-xl border border-border mb-4">
        {!showCreateKey ? (
          <button
            onClick={() => setShowCreateKey(true)}
            className="px-5 py-2.5 border-none rounded-md cursor-pointer text-sm"
            style={{
              background: theme.accent,
              color: theme.accentText,
            }}
          >
            + Create New API Key
          </button>
        ) : (
          <form onSubmit={createAPIKey}>
            <div className="mb-4">
              <label className="block text-sm text-muted mb-1.5">
                Key Name
              </label>
              <input
                type="text"
                value={newKeyName}
                onInput={e => setNewKeyName((e.target as HTMLInputElement).value)}
                placeholder="e.g., Chrome Extension, Mobile App..."
                className="w-full px-3.5 py-2.5 border rounded-md text-sm box-border"
                style={{
                  borderColor: theme.borderInput,
                  background: theme.bgInput,
                  color: theme.text,
                }}
              />
            </div>

            <div className="mb-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={isAdminKey}
                  onChange={e => setIsAdminKey((e.target as HTMLInputElement).checked)}
                />
                <span style={{ color: theme.text }}>Admin key (all permissions)</span>
              </label>
            </div>

            {!isAdminKey && (
              <div className="mb-4">
                <label className="block text-sm text-muted mb-2">
                  Scopes
                </label>
                <div className="flex flex-wrap gap-2">
                  {availableScopes.map(scope => (
                    <label
                      key={scope}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md cursor-pointer text-[13px]"
                      style={{
                        background: newKeyScopes.includes(scope) ? theme.accent : theme.bgHover,
                        color: newKeyScopes.includes(scope) ? theme.accentText : theme.text,
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
                        className="hidden"
                      />
                      {scope}
                    </label>
                  ))}
                </div>
              </div>
            )}

            <div className="flex gap-2">
              <button
                type="submit"
                disabled={!newKeyName.trim() || (!isAdminKey && newKeyScopes.length === 0)}
                className="px-5 py-2.5 border-none rounded-md text-sm"
                style={{
                  background: newKeyName.trim() && (isAdminKey || newKeyScopes.length > 0)
                    ? theme.accent
                    : theme.textDisabled,
                  color: newKeyName.trim() && (isAdminKey || newKeyScopes.length > 0)
                    ? theme.accentText
                    : theme.textSubtle,
                  cursor: newKeyName.trim() && (isAdminKey || newKeyScopes.length > 0)
                    ? 'pointer'
                    : 'not-allowed',
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
                className="px-5 py-2.5 border-none rounded-md cursor-pointer text-sm"
                style={{
                  background: theme.bgHover,
                  color: theme.textMuted,
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
        <div className="flex flex-col gap-2">
          {apiKeys.map(key => (
            <div
              key={key.id}
              className="p-4 bg-card rounded-lg border border-border flex justify-between items-center flex-wrap gap-3"
            >
              <div>
                <div className="font-semibold mb-1" style={{ color: theme.text }}>
                  {key.name}
                </div>
                <div className="text-xs text-muted">
                  <code className="px-1.5 py-0.5 rounded" style={{ background: theme.bgMuted }}>
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
                className="px-3 py-1.5 border-none rounded cursor-pointer text-[13px]"
                style={{
                  background: theme.errorBg,
                  color: theme.errorText,
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
