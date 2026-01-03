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
      className="fixed inset-0 flex items-center justify-center z-[1000]"
      style={{ background: theme.overlay }}
      onClick={onClose}
    >
      <div
        className="rounded-xl p-6 w-full max-w-[600px] max-h-[80vh] overflow-auto"
        style={{ background: theme.bgCard }}
        onClick={e => e.stopPropagation()}
      >
        <h2 className="m-0 mb-5 text-xl" style={{ color: theme.text }}>Edit Kind: {kind.name}</h2>
        <form onSubmit={handleSave}>
          <div className="flex gap-3 mb-4 items-end">
            <div>
              <label className="block mb-1.5 text-sm font-medium" style={{ color: theme.text }}>Icon</label>
              <EmojiPicker value={icon} onChange={setIcon} usedEmojis={usedEmojis} theme={theme} />
            </div>
            <div className="flex-1">
              <label className="block mb-1.5 text-sm font-medium" style={{ color: theme.text }}>Name</label>
              <input
                type="text"
                value={name}
                onInput={e => setName((e.target as HTMLInputElement).value)}
                className="w-full px-3.5 py-2.5 border rounded-md box-border"
                style={{ border: `1px solid ${theme.borderInput}`, background: theme.bgInput, color: theme.text }}
              />
            </div>
          </div>

          {/* Template selector */}
          <div className="mb-4">
            <label className="block mb-1.5 text-sm font-medium" style={{ color: theme.text }}>Display Template</label>
            <div className="flex gap-2 flex-wrap">
              {TEMPLATES.map(t => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setTemplate(t.id as Kind['template'])}
                  className="px-3.5 py-2 rounded-md cursor-pointer text-[13px]"
                  style={{
                    border: template === t.id ? `2px solid ${theme.accent}` : `1px solid ${theme.borderInput}`,
                    background: template === t.id ? theme.bgHover : theme.bgInput,
                    color: theme.text,
                  }}
                  title={t.description}
                >
                  {t.name}
                </button>
              ))}
            </div>
            <p className="text-xs mt-1" style={{ color: theme.textMuted }}>
              {TEMPLATES.find(t => t.id === template)?.description}
            </p>
          </div>

          {/* Interaction settings */}
          <div className="mb-5 p-4 rounded-lg" style={{ background: theme.bgSubtle }}>
            <label className="block mb-3 text-sm font-medium" style={{ color: theme.text }}>Interactions</label>
            <div className="flex flex-col gap-3">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={reactable}
                  onChange={e => setReactable((e.target as HTMLInputElement).checked)}
                  className="w-[18px] h-[18px] cursor-pointer"
                />
                <span className="text-sm" style={{ color: theme.text }}>Allow reactions</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={commentable}
                  onChange={e => setCommentable((e.target as HTMLInputElement).checked)}
                  className="w-[18px] h-[18px] cursor-pointer"
                />
                <span className="text-sm" style={{ color: theme.text }}>Allow replies</span>
              </label>
              {!commentable && (
                <label className="flex items-center gap-2 cursor-pointer ml-[26px]">
                  <input
                    type="checkbox"
                    checked={showExistingComments}
                    onChange={e => setShowExistingComments((e.target as HTMLInputElement).checked)}
                    className="w-4 h-4 cursor-pointer"
                  />
                  <span className="text-[13px]" style={{ color: theme.textMuted }}>Show existing replies (read-only)</span>
                </label>
              )}
            </div>
          </div>

          <div className="mb-5">
            <div className="flex justify-between items-center mb-3">
              <label className="text-sm font-medium" style={{ color: theme.text }}>Attributes</label>
              <button
                type="button"
                onClick={addAttribute}
                className="px-3 py-1.5 border-none rounded cursor-pointer text-[13px]"
                style={{ background: theme.bgHover, color: theme.text }}
              >
                + Add Attribute
              </button>
            </div>

            {attributes.length === 0 ? (
              <p className="text-sm text-center p-5 rounded-lg" style={{ color: theme.textSubtle, background: theme.bgSubtle }}>
                No attributes. Add one to define fields for this kind.
              </p>
            ) : (
              <div className="flex flex-col gap-2">
                {attributes.map((attr, i) => (
                  <div key={i} className="p-3 rounded-lg" style={{ background: theme.bgSubtle }}>
                    <div className="flex gap-2 items-center" style={{ marginBottom: attr.type === 'select' ? 8 : 0 }}>
                      <input
                        type="text"
                        value={attr.name}
                        placeholder="Field name"
                        onInput={e => updateAttribute(i, 'name', (e.target as HTMLInputElement).value)}
                        className="flex-1 px-2.5 py-2 border rounded text-[13px]"
                        style={{ border: `1px solid ${theme.borderInput}`, background: theme.bgInput, color: theme.text }}
                      />
                      <select
                        value={attr.type}
                        onChange={e => updateAttribute(i, 'type', (e.target as HTMLSelectElement).value)}
                        className="px-2.5 py-2 border rounded text-[13px]"
                        style={{ border: `1px solid ${theme.borderInput}`, background: theme.bgInput, color: theme.text }}
                      >
                        <option value="text">Text</option>
                        <option value="number">Number</option>
                        <option value="date">Date</option>
                        <option value="url">URL</option>
                        <option value="checkbox">Checkbox</option>
                        <option value="select">Select</option>
                      </select>
                      <label className="flex items-center gap-1 text-[13px] whitespace-nowrap" style={{ color: theme.text }}>
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
                        className="px-2 py-1 bg-transparent border-none cursor-pointer text-base"
                        style={{ color: theme.errorText }}
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
                          className="w-full px-2.5 py-2 border rounded text-[13px] box-border"
                          style={{ border: `1px solid ${theme.borderInput}`, background: theme.bgInput, color: theme.text }}
                        />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="flex gap-2 justify-end">
            <button
              type="button"
              onClick={onClose}
              className="px-5 py-2.5 border-none rounded-md cursor-pointer"
              style={{ background: theme.bgHover, color: theme.text }}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-5 py-2.5 border-none rounded-md cursor-pointer"
              style={{ background: theme.accent, color: theme.accentText }}
            >
              Save
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
