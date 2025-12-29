import { useState } from 'preact/hooks'
import { Theme } from '../theme'
import { Kind, Attribute, TEMPLATES } from '../types'
import { EmojiPicker } from './EmojiPicker'

interface EditKindModalProps {
  kind: Kind
  onSave: (k: Kind) => void
  onClose: () => void
  usedEmojis: string[]
  theme: Theme
}

export function EditKindModal({
  kind,
  onSave,
  onClose,
  usedEmojis,
  theme,
}: EditKindModalProps) {
  const [name, setName] = useState(kind.name)
  const [icon, setIcon] = useState(kind.icon || '')
  const [template, setTemplate] = useState<Kind['template']>(kind.template || 'default')
  const [attributes, setAttributes] = useState<Attribute[]>(kind.attributes || [])
  const [commentable, setCommentable] = useState(kind.commentable ?? false)
  const [showExistingComments, setShowExistingComments] = useState(kind.show_existing_comments ?? false)
  const [reactable, setReactable] = useState(kind.reactable ?? true)

  function addAttribute() {
    setAttributes([...attributes, { name: '', type: 'text', required: false, options: '' }])
  }

  function updateAttribute(index: number, field: keyof Attribute, value: string | boolean) {
    const updated = [...attributes]
    updated[index] = { ...updated[index], [field]: value }
    setAttributes(updated)
  }

  function removeAttribute(index: number) {
    setAttributes(attributes.filter((_, i) => i !== index))
  }

  function handleSave(e: Event) {
    e.preventDefault()
    onSave({ ...kind, name, icon, template, attributes, commentable, show_existing_comments: showExistingComments, reactable })
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
          width: '100%',
          maxWidth: 600,
          maxHeight: '80vh',
          overflow: 'auto',
        }}
        onClick={e => e.stopPropagation()}
      >
        <h2 style={{ margin: '0 0 20px', fontSize: 20, color: theme.text }}>Edit Kind: {kind.name}</h2>
        <form onSubmit={handleSave}>
          <div style={{ display: 'flex', gap: 12, marginBottom: 16, alignItems: 'flex-end' }}>
            <div>
              <label style={{ display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500, color: theme.text }}>Icon</label>
              <EmojiPicker value={icon} onChange={setIcon} usedEmojis={usedEmojis} theme={theme} />
            </div>
            <div style={{ flex: 1 }}>
              <label style={{ display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500, color: theme.text }}>Name</label>
              <input
                type="text"
                value={name}
                onInput={e => setName((e.target as HTMLInputElement).value)}
                style={{ width: '100%', padding: '10px 14px', border: `1px solid ${theme.borderInput}`, borderRadius: 6, boxSizing: 'border-box', background: theme.bgInput, color: theme.text }}
              />
            </div>
          </div>

          {/* Template selector */}
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500, color: theme.text }}>Display Template</label>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {TEMPLATES.map(t => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setTemplate(t.id as Kind['template'])}
                  style={{
                    padding: '8px 14px',
                    border: template === t.id ? `2px solid ${theme.accent}` : `1px solid ${theme.borderInput}`,
                    borderRadius: 6,
                    background: template === t.id ? theme.bgHover : theme.bgInput,
                    color: theme.text,
                    cursor: 'pointer',
                    fontSize: 13,
                  }}
                  title={t.description}
                >
                  {t.name}
                </button>
              ))}
            </div>
            <p style={{ fontSize: 12, color: theme.textMuted, marginTop: 4 }}>
              {TEMPLATES.find(t => t.id === template)?.description}
            </p>
          </div>

          {/* Interaction settings */}
          <div style={{ marginBottom: 20, padding: 16, background: theme.bgSubtle, borderRadius: 8 }}>
            <label style={{ display: 'block', marginBottom: 12, fontSize: 14, fontWeight: 500, color: theme.text }}>Interactions</label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={reactable}
                  onChange={e => setReactable((e.target as HTMLInputElement).checked)}
                  style={{ width: 18, height: 18, cursor: 'pointer' }}
                />
                <span style={{ fontSize: 14, color: theme.text }}>Allow reactions</span>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={commentable}
                  onChange={e => setCommentable((e.target as HTMLInputElement).checked)}
                  style={{ width: 18, height: 18, cursor: 'pointer' }}
                />
                <span style={{ fontSize: 14, color: theme.text }}>Allow replies</span>
              </label>
              {!commentable && (
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', marginLeft: 26 }}>
                  <input
                    type="checkbox"
                    checked={showExistingComments}
                    onChange={e => setShowExistingComments((e.target as HTMLInputElement).checked)}
                    style={{ width: 16, height: 16, cursor: 'pointer' }}
                  />
                  <span style={{ fontSize: 13, color: theme.textMuted }}>Show existing replies (read-only)</span>
                </label>
              )}
            </div>
          </div>

          <div style={{ marginBottom: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <label style={{ fontSize: 14, fontWeight: 500, color: theme.text }}>Attributes</label>
              <button
                type="button"
                onClick={addAttribute}
                style={{
                  padding: '6px 12px',
                  background: theme.bgHover,
                  color: theme.text,
                  border: 'none',
                  borderRadius: 4,
                  cursor: 'pointer',
                  fontSize: 13,
                }}
              >
                + Add Attribute
              </button>
            </div>

            {attributes.length === 0 ? (
              <p style={{ color: theme.textSubtle, fontSize: 14, textAlign: 'center', padding: 20, background: theme.bgSubtle, borderRadius: 8 }}>
                No attributes. Add one to define fields for this kind.
              </p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {attributes.map((attr, i) => (
                  <div key={i} style={{ padding: 12, background: theme.bgSubtle, borderRadius: 8 }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: attr.type === 'select' ? 8 : 0 }}>
                      <input
                        type="text"
                        value={attr.name}
                        placeholder="Field name"
                        onInput={e => updateAttribute(i, 'name', (e.target as HTMLInputElement).value)}
                        style={{ flex: 1, padding: '8px 10px', border: `1px solid ${theme.borderInput}`, borderRadius: 4, fontSize: 13, background: theme.bgInput, color: theme.text }}
                      />
                      <select
                        value={attr.type}
                        onChange={e => updateAttribute(i, 'type', (e.target as HTMLSelectElement).value)}
                        style={{ padding: '8px 10px', border: `1px solid ${theme.borderInput}`, borderRadius: 4, fontSize: 13, background: theme.bgInput, color: theme.text }}
                      >
                        <option value="text">Text</option>
                        <option value="number">Number</option>
                        <option value="date">Date</option>
                        <option value="url">URL</option>
                        <option value="checkbox">Checkbox</option>
                        <option value="select">Select</option>
                      </select>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 13, whiteSpace: 'nowrap', color: theme.text }}>
                        <input
                          type="checkbox"
                          checked={attr.required}
                          onChange={e => updateAttribute(i, 'required', (e.target as HTMLInputElement).checked)}
                        />
                        Required
                      </label>
                      <button
                        type="button"
                        onClick={() => removeAttribute(i)}
                        style={{ padding: '4px 8px', background: 'none', border: 'none', color: theme.errorText, cursor: 'pointer', fontSize: 16 }}
                      >
                        ×
                      </button>
                    </div>

                    {/* Options input for select type */}
                    {attr.type === 'select' && (
                      <div>
                        <input
                          type="text"
                          value={attr.options}
                          placeholder="Options (comma-separated): option1, option2, option3"
                          onInput={e => updateAttribute(i, 'options', (e.target as HTMLInputElement).value)}
                          style={{ width: '100%', padding: '8px 10px', border: `1px solid ${theme.borderInput}`, borderRadius: 4, fontSize: 13, boxSizing: 'border-box', background: theme.bgInput, color: theme.text }}
                        />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '10px 20px',
                background: theme.bgHover,
                color: theme.text,
                border: 'none',
                borderRadius: 6,
                cursor: 'pointer',
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              style={{
                padding: '10px 20px',
                background: theme.accent,
                color: theme.accentText,
                border: 'none',
                borderRadius: 6,
                cursor: 'pointer',
              }}
            >
              Save
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
