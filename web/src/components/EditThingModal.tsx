import { useState } from 'preact/hooks'
import { Theme } from '../theme'
import { Thing, Kind, Attribute } from '../types'
import { apiUrl } from '../api'

// Attribute input component for editing metadata
function AttributeInput({
  attribute,
  value,
  onChange,
  theme,
}: {
  attribute: Attribute
  value: unknown
  onChange: (val: unknown) => void
  theme: Theme
}) {
  const commonStyle = {
    border: `1px solid ${theme.borderInput}`,
    background: theme.bgInput,
    color: theme.text,
  }

  switch (attribute.type) {
    case 'number':
      return (
        <div>
          <label className="block mb-1 text-xs" style={{ color: theme.textSubtle }}>
            {attribute.name}{attribute.required && ' *'}
          </label>
          <input
            type="number"
            value={value as number || ''}
            onInput={e => onChange(parseFloat((e.target as HTMLInputElement).value) || null)}
            className="w-full px-3.5 py-2.5 rounded-md text-sm box-border"
            style={commonStyle}
          />
        </div>
      )
    case 'date':
      return (
        <div>
          <label className="block mb-1 text-xs" style={{ color: theme.textSubtle }}>
            {attribute.name}{attribute.required && ' *'}
          </label>
          <input
            type="date"
            value={value as string || ''}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            className="w-full px-3.5 py-2.5 rounded-md text-sm box-border"
            style={commonStyle}
          />
        </div>
      )
    case 'url':
      return (
        <div>
          <label className="block mb-1 text-xs" style={{ color: theme.textSubtle }}>
            {attribute.name}{attribute.required && ' *'}
          </label>
          <input
            type="url"
            value={value as string || ''}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            placeholder="https://..."
            className="w-full px-3.5 py-2.5 rounded-md text-sm box-border"
            style={commonStyle}
          />
        </div>
      )
    case 'checkbox':
      return (
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={value as boolean || false}
            onChange={e => onChange((e.target as HTMLInputElement).checked)}
            className="w-[18px] h-[18px] cursor-pointer"
          />
          <span className="text-sm" style={{ color: theme.text }}>{attribute.name}</span>
        </label>
      )
    case 'select':
      const options = attribute.options?.split(',').map(o => o.trim()).filter(Boolean) || []
      return (
        <div>
          <label className="block mb-1 text-xs" style={{ color: theme.textSubtle }}>
            {attribute.name}{attribute.required && ' *'}
          </label>
          <select
            value={value as string || ''}
            onChange={e => onChange((e.target as HTMLSelectElement).value)}
            className="w-full px-3.5 py-2.5 rounded-md text-sm box-border"
            style={commonStyle}
          >
            <option value="">Select...</option>
            {options.map(opt => (
              <option key={opt} value={opt}>{opt}</option>
            ))}
          </select>
        </div>
      )
    default:
      return (
        <div>
          <label className="block mb-1 text-xs" style={{ color: theme.textSubtle }}>
            {attribute.name}{attribute.required && ' *'}
          </label>
          <input
            type="text"
            value={value as string || ''}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            className="w-full px-3.5 py-2.5 rounded-md text-sm box-border"
            style={commonStyle}
          />
        </div>
      )
  }
}

interface EditThingModalProps {
  thing: Thing
  kinds: Kind[]
  onSave: (t: Thing) => void
  onClose: () => void
  theme: Theme
}

export function EditThingModal({
  thing,
  kinds,
  onSave,
  onClose,
  theme,
}: EditThingModalProps) {
  const [content, setContent] = useState(thing.content)
  const [type, setType] = useState(thing.type)
  const [metadata, setMetadata] = useState<Record<string, unknown>>(thing.metadata || {})
  const [photoCaptions, setPhotoCaptions] = useState<Record<string, string>>(
    thing.photos?.reduce((acc, p) => ({ ...acc, [p.id]: p.caption || '' }), {}) || {}
  )
  const [deletedPhotoIds, setDeletedPhotoIds] = useState<string[]>([])
  const [saving, setSaving] = useState(false)

  const currentKind = kinds.find(k => k.name === type)
  const isGallery = thing.type === 'gallery' && thing.photos && thing.photos.length > 0

  // Filter out deleted photos for display
  const visiblePhotos = thing.photos?.filter(p => !deletedPhotoIds.includes(p.id)) || []

  async function handleSave(e: Event) {
    e.preventDefault()
    setSaving(true)

    try {
      // Delete photos that were marked for deletion
      for (const photoId of deletedPhotoIds) {
        await fetch(apiUrl(`/api/photos/${photoId}`), {
          method: 'DELETE',
          credentials: 'include',
        })
      }

      // Save photo captions if this is a gallery
      if (isGallery && thing.photos) {
        for (const photo of thing.photos) {
          // Skip deleted photos
          if (deletedPhotoIds.includes(photo.id)) continue

          const newCaption = photoCaptions[photo.id] || ''
          if (newCaption !== (photo.caption || '')) {
            await fetch(apiUrl(`/api/photos/${photo.id}`), {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ caption: newCaption }),
              credentials: 'include',
            })
          }
        }
      }

      // Build updated photos array with new captions, excluding deleted photos
      const updatedPhotos = thing.photos
        ?.filter(p => !deletedPhotoIds.includes(p.id))
        .map(p => ({ ...p, caption: photoCaptions[p.id] || p.caption }))

      // Save the thing with updated photos
      onSave({ ...thing, content, type, metadata, photos: updatedPhotos })
    } catch (err) {
      console.error('Failed to save:', err)
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
        className="rounded-xl p-6 w-full max-w-[500px] max-h-[80vh] overflow-auto"
        style={{ background: theme.bgCard }}
        onClick={e => e.stopPropagation()}
      >
        <h2 className="m-0 mb-5 text-xl" style={{ color: theme.text }}>Edit Thing</h2>
        <form onSubmit={handleSave}>
          <div className="mb-4">
            <label className="block mb-1.5 text-sm font-medium" style={{ color: theme.text }}>Kind</label>
            <select
              value={type}
              onChange={e => {
                setType((e.target as HTMLSelectElement).value)
                setMetadata({})
              }}
              className="w-full px-3.5 py-2.5 rounded-md text-sm"
              style={{
                border: `1px solid ${theme.borderInput}`,
                background: theme.bgInput,
                color: theme.text,
              }}
            >
              {kinds.map(kind => (
                <option key={kind.id} value={kind.name}>{kind.icon} {kind.name}</option>
              ))}
            </select>
          </div>
          <div className="mb-4">
            <label className="block mb-1.5 text-sm font-medium" style={{ color: theme.text }}>Content</label>
            <textarea
              value={content}
              onInput={e => setContent((e.target as HTMLTextAreaElement).value)}
              rows={4}
              className="w-full px-3.5 py-2.5 rounded-md text-sm resize-y box-border"
              style={{
                border: `1px solid ${theme.borderInput}`,
                background: theme.bgInput,
                color: theme.text,
              }}
            />
          </div>

          {/* Kind attributes */}
          {currentKind?.attributes && currentKind.attributes.length > 0 && (
            <div className="mb-4 flex flex-col gap-3">
              <label className="text-sm font-medium" style={{ color: theme.text }}>Attributes</label>
              {currentKind.attributes.map(attr => (
                <AttributeInput
                  key={attr.name}
                  attribute={attr}
                  value={metadata[attr.name]}
                  onChange={val => setMetadata({ ...metadata, [attr.name]: val })}
                  theme={theme}
                />
              ))}
            </div>
          )}

          {/* Photo captions for galleries */}
          {isGallery && visiblePhotos.length > 0 && (
            <div className="mb-4">
              <label className="block mb-2 text-sm font-medium" style={{ color: theme.text }}>
                Photos ({visiblePhotos.length})
              </label>
              <div className="flex flex-col gap-3">
                {visiblePhotos.map((photo, index) => (
                  <div key={photo.id} className="flex gap-2 items-center">
                    <img
                      src={apiUrl(`/api/photos/${photo.id}?size=thumb`)}
                      alt={`Photo ${index + 1}`}
                      className="w-[60px] h-[60px] object-cover rounded shrink-0"
                    />
                    <input
                      type="text"
                      value={photoCaptions[photo.id] || ''}
                      onChange={e => setPhotoCaptions({ ...photoCaptions, [photo.id]: (e.target as HTMLInputElement).value })}
                      placeholder={`Caption for photo ${index + 1}`}
                      className="flex-1 px-3 py-2 rounded-md text-xs"
                      style={{
                        border: `1px solid ${theme.borderInput}`,
                        background: theme.bgInput,
                        color: theme.text,
                      }}
                    />
                    <button
                      type="button"
                      onClick={() => setDeletedPhotoIds([...deletedPhotoIds, photo.id])}
                      className="bg-transparent border-0 cursor-pointer text-lg px-2 py-1 shrink-0"
                      style={{ color: theme.error }}
                      title="Delete photo"
                    >
                      🗑️
                    </button>
                  </div>
                ))}
              </div>
              {deletedPhotoIds.length > 0 && (
                <p className="text-xs mt-2" style={{ color: theme.textMuted }}>
                  {deletedPhotoIds.length} photo(s) will be deleted when you save
                </p>
              )}
            </div>
          )}

          <div className="flex gap-2 justify-end">
            <button
              type="button"
              onClick={onClose}
              className="px-5 py-2.5 rounded-md border-0 cursor-pointer"
              style={{
                background: theme.bgHover,
                color: theme.text,
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-5 py-2.5 rounded-md border-0"
              style={{
                background: saving ? theme.textMuted : theme.accent,
                color: theme.accentText,
                cursor: saving ? 'not-allowed' : 'pointer',
                opacity: saving ? 0.7 : 1,
              }}
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
